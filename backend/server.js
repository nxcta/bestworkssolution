import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENV_PATH = path.join(__dirname, '.env');
if (fs.existsSync(ENV_PATH)) {
  for (const line of fs.readFileSync(ENV_PATH, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq < 1) continue;
    const k = t.slice(0, eq).trim();
    let v = t.slice(eq + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (!process.env[k]) process.env[k] = v;
  }
}

const DATA_DIR = path.join(__dirname, 'data');
const BOOKINGS_FILE = path.join(DATA_DIR, 'bookings.jsonl');
const CALENDLY_EVENTS_FILE = path.join(DATA_DIR, 'calendly_events.jsonl');
const IDEMPOTENCY_FILE = path.join(DATA_DIR, 'idempotency.json');

const CALENDLY_SIGNING_KEY = process.env.CALENDLY_WEBHOOK_SIGNING_KEY || '';
const CALENDLY_SKIP_VERIFY = /^(1|true|yes|on)$/i.test(
  String(process.env.CALENDLY_SKIP_VERIFY || '').trim(),
);

const WEBHOOK_WINDOW_MS = 10 * 60 * 1000;
const WEBHOOK_MAX_PER_WINDOW = 200;
const webhookIpHits = new Map();

const PORT = Number(process.env.PORT) || 3847;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const BUSINESS_TZ = process.env.BUSINESS_TZ || 'Asia/Manila';
const TEAM_NOTIFY_EMAIL = process.env.TEAM_NOTIFY_EMAIL || 'bestworkssolutions@gmail.com';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM = process.env.RESEND_FROM || '';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const ADMIN_BASIC_USER = process.env.ADMIN_BASIC_USER || '';
const ADMIN_BASIC_PASS = process.env.ADMIN_BASIC_PASS || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX = 8;
const ipHits = new Map();

const ADMIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const ADMIN_RATE_MAX = 40;
const adminIpHits = new Map();

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadIdempotency() {
  try {
    const raw = fs.readFileSync(IDEMPOTENCY_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function saveIdempotency(map) {
  const pruned = {};
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [k, v] of Object.entries(map)) {
    if (v.ts > cutoff) pruned[k] = v;
  }
  fs.writeFileSync(IDEMPOTENCY_FILE, JSON.stringify(pruned), 'utf8');
}

function rateLimitBooking(ip) {
  const now = Date.now();
  let arr = ipHits.get(ip) || [];
  arr = arr.filter((t) => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) return false;
  arr.push(now);
  ipHits.set(ip, arr);
  return true;
}

function rateLimitAdmin(ip) {
  const now = Date.now();
  let arr = adminIpHits.get(ip) || [];
  arr = arr.filter((t) => now - t < ADMIN_RATE_WINDOW_MS);
  if (arr.length >= ADMIN_RATE_MAX) return false;
  arr.push(now);
  adminIpHits.set(ip, arr);
  return true;
}

function rateLimitWebhook(ip) {
  const now = Date.now();
  let arr = webhookIpHits.get(ip) || [];
  arr = arr.filter((t) => now - t < WEBHOOK_WINDOW_MS);
  if (arr.length >= WEBHOOK_MAX_PER_WINDOW) return false;
  arr.push(now);
  webhookIpHits.set(ip, arr);
  return true;
}

function verifyCalendlySignature(rawUtf8, headerVal) {
  if (CALENDLY_SKIP_VERIFY) return true;
  if (!CALENDLY_SIGNING_KEY || !headerVal || typeof headerVal !== 'string') return false;
  let tToken;
  let v1Sig;
  for (const part of headerVal.split(',').map((p) => p.trim())) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === 't') tToken = v;
    if (k === 'v1') v1Sig = v;
  }
  if (!tToken || !v1Sig) return false;
  const signingKey = CALENDLY_SIGNING_KEY.replace(/^whsec_/i, '');
  try {
    const expectedHex = crypto
      .createHmac('sha256', signingKey)
      .update(`${tToken}.${rawUtf8}`, 'utf8')
      .digest('hex');
    const a = Buffer.from(v1Sig.trim(), 'hex');
    const b = Buffer.from(expectedHex, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function stableCalRef(inviteeUri) {
  const h = crypto.createHash('sha256').update(inviteeUri || '', 'utf8').digest('hex').slice(0, 12).toUpperCase();
  return `CAL-${h}`;
}

function normalizeCalendlyWebhook(bodyInput) {
  let body =
    typeof bodyInput === 'string'
      ? (() => {
          try {
            return JSON.parse(bodyInput);
          } catch {
            return null;
          }
        })()
      : bodyInput;
  if (!body || typeof body !== 'object') return null;
  const webhookEvent = String(body.event || '');
  const p = body.payload || {};
  const inviteeUri = String(p.uri || p.invitee?.uri || '');
  const inviteeEmail = String(p.email || '').toLowerCase().trim();
  const fullName = String(p.name || `${String(p.first_name || '').trim()} ${String(p.last_name || '').trim()}`.trim() || '').trim();
  const se =
    typeof p.scheduled_event === 'object' && p.scheduled_event !== null ? p.scheduled_event : {};
  let scheduledStart =
    typeof p.start_time !== 'undefined' ? p.start_time : se.start_time || se.starts_at || null;
  let scheduledEnd = typeof p.end_time !== 'undefined' ? p.end_time : se.end_time || null;
  const calendarEventUri =
    typeof p.scheduled_event === 'string' ? p.scheduled_event : se.uri || p.event || null;
  let firstName = String(p.first_name || '').trim();
  let lastName = String(p.last_name || '').trim();
  if (!firstName && fullName) {
    const parts = fullName.split(/\s+/);
    firstName = parts.shift() || '';
    lastName = parts.join(' ');
  }

  const ref = inviteeUri ? stableCalRef(inviteeUri) : `CAL-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const createdAt = body.created_at || p.created_at || new Date().toISOString();

  let status = String(p.status || 'active').toLowerCase();
  if (webhookEvent === 'invitee.canceled' || p.canceled === true || p.cancelled === true || p.active === false) {
    status = 'canceled';
  }

  return {
    source: 'calendly',
    ref,
    webhookEvent,
    receivedAt: new Date().toISOString(),
    createdAt: String(createdAt),
    status,
    inviteeUri,
    inviteeEmail: inviteeEmail || null,
    firstName: firstName || fullName.split(' ')[0] || null,
    lastName: lastName || '',
    timezone: String(p.timezone || '').slice(0, 80) || null,
    scheduledStart: scheduledStart ? String(scheduledStart) : null,
    scheduledEnd: scheduledEnd ? String(scheduledEnd) : null,
    scheduledEventUri: calendarEventUri ? String(calendarEventUri) : null,
    rescheduleUrl: p.reschedule_url ? String(p.reschedule_url) : null,
    cancelUrl: p.cancel_url ? String(p.cancel_url) : null,
  };
}

function readAllCalendlyRows() {
  ensureDataDir();
  if (!fs.existsSync(CALENDLY_EVENTS_FILE)) return [];
  const lines = fs.readFileSync(CALENDLY_EVENTS_FILE, 'utf8').split('\n').filter(Boolean);
  const out = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line));
    } catch {
      /* skip */
    }
  }
  return out;
}

function mapWebsiteToUnified(row) {
  return {
    source: 'website',
    ref: row.ref,
    webhookEventOrService: row.service || 'website',
    createdAt: row.createdAt,
    status: row.status,
    email: row.email,
    firstName: row.firstName,
    lastName: row.lastName,
    scheduledDate: row.scheduledDate || null,
    scheduledTime: row.scheduledTime || null,
    scheduledAtUtc: row.scheduledAtUtc || null,
    phone: row.phone,
    inviteeUri: null,
    eventNote: row.goal || row.notes || null,
    rawWebhookEvent: null,
  };
}

function mapCalendlyToUnified(row) {
  return {
    source: 'calendly',
    ref: row.ref,
    webhookEventOrService: row.webhookEvent,
    createdAt: row.createdAt || row.receivedAt,
    status: row.status,
    email: row.inviteeEmail,
    firstName: row.firstName,
    lastName: row.lastName,
    scheduledDate: row.scheduledStart ? String(row.scheduledStart).slice(0, 10) : null,
    scheduledTime: row.scheduledStart ? String(row.scheduledStart).slice(11, 16) || null : null,
    scheduledAtUtc: row.scheduledStart || null,
    phone: null,
    inviteeUri: row.inviteeUri,
    eventNote: row.scheduledEventUri || null,
    rawWebhookEvent: row.webhookEvent,
  };
}

function buildUnifiedTimeline() {
  const website = readAllBookings().map(mapWebsiteToUnified);
  const cal = readAllCalendlyRows().map(mapCalendlyToUnified);
  const merged = [...website, ...cal];
  merged.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return merged;
}

function aggregateMetrics(days) {
  const unified = [...readAllBookings().map(mapWebsiteToUnified), ...readAllCalendlyRows().map(mapCalendlyToUnified)];
  const byDayMap = {};
  const dayKeys = [];
  const now = new Date();
  now.setUTCHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - i);
    const k = d.toISOString().slice(0, 10);
    dayKeys.push(k);
    byDayMap[k] = { date: k, website: 0, calendly: 0 };
  }
  let tw = 0;
  let tc = 0;
  for (const r of unified) {
    const iso = String(r.createdAt || '');
    const day = iso.slice(0, 10);
    if (byDayMap[day]) {
      if (r.source === 'website') byDayMap[day].website += 1;
      else byDayMap[day].calendly += 1;
    }
    if (r.source === 'website') tw += 1;
    else tc += 1;
  }
  const series = dayKeys.map((k) => byDayMap[k]);
  let w7 = 0;
  let c7 = 0;
  const cutoff = Date.now() - 7 * 86400000;
  for (const r of unified) {
    const t = Date.parse(String(r.createdAt || ''));
    if (!Number.isNaN(t) && t >= cutoff) {
      if (r.source === 'website') w7 += 1;
      else c7 += 1;
    }
  }
  return {
    kpis: {
      appointmentsWebsiteTotal: tw,
      appointmentsCalendlyTotal: tc,
      appointmentsAll: tw + tc,
      appointmentsLast7Website: w7,
      appointmentsLast7Calendly: c7,
    },
    series,
    note: 'Appointments counts by created/received timestamp (UTC day). Revenue not included.',
  };
}

/** Constant-length compare via SHA-256 (avoids length leaks from timingSafeEqual on raw strings). */
function secretEquals(expected, received) {
  if (typeof expected !== 'string' || typeof received !== 'string' || !expected.length) return false;
  const a = crypto.createHash('sha256').update(expected, 'utf8').digest();
  const b = crypto.createHash('sha256').update(received, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

function parseBasicAuth(header) {
  if (!header || typeof header !== 'string' || !header.startsWith('Basic ')) return null;
  try {
    const raw = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    const i = raw.indexOf(':');
    if (i < 0) return null;
    return { user: raw.slice(0, i), pass: raw.slice(i + 1) };
  } catch {
    return null;
  }
}

/** HTTP Basic: only for loading the admin HTML shell. API routes use Bearer token only (avoids browser auth popup on fetch). */
function optionalBasicAuthAdminShell(req, res, next) {
  if (!ADMIN_BASIC_USER || !ADMIN_BASIC_PASS) return next();
  const creds = parseBasicAuth(req.headers.authorization);
  if (!creds || !secretEquals(ADMIN_BASIC_USER, creds.user) || !secretEquals(ADMIN_BASIC_PASS, creds.pass)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="BWS Admin", charset="UTF-8"');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(401).type('text/plain').send('Authentication required');
  }
  return next();
}

function parseTimeTo24(hm, ampm) {
  let [h, m] = hm.split(':').map(Number);
  if (ampm === 'PM' && h !== 12) h += 12;
  if (ampm === 'AM' && h === 12) h = 0;
  return { h, m: m || 0 };
}

function manilaWallToUtcIso(year, monthIndex, day, timeStr) {
  const parts = String(timeStr).trim().split(/\s+/);
  if (parts.length < 2) return null;
  const { h, m } = parseTimeTo24(parts[0], parts[1]);
  const y = year;
  const mo = monthIndex + 1;
  const d = day;
  const pad = (n) => String(n).padStart(2, '0');
  const isoLocal = `${y}-${pad(mo)}-${pad(d)}T${pad(h)}:${pad(m)}:00`;
  const dObj = new Date(`${isoLocal}+08:00`);
  if (Number.isNaN(dObj.getTime())) return null;
  return dObj.toISOString();
}

function refFromBody() {
  return `BWS-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

async function sendResend(to, subject, html) {
  if (!RESEND_API_KEY || !RESEND_FROM) return { skipped: true };
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: RESEND_FROM, to: [to], subject, html }),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Resend ${res.status}: ${t}`);
  }
  return res.json();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: IS_PROD ? { maxAge: 15552000, includeSubDomains: true, preload: false } : false,
  })
);

app.use(
  cors({
    origin(origin, cb) {
      if (!ALLOWED_ORIGINS.length) {
        if (IS_PROD) {
          return cb(null, false);
        }
        return cb(null, true);
      }
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Idempotency-Key', 'Authorization', 'Accept'],
    maxAge: 86400,
  })
);

app.post(
  '/webhooks/calendly',
  express.raw({
    limit: '512kb',
    type: (req) => {
      const ct = req.headers['content-type'];
      return typeof ct === 'string' && ct.toLowerCase().includes('application/json');
    },
  }),
  (req, res) => {
    const ip = clientIp(req);
    if (!rateLimitWebhook(ip)) {
      return res.status(429).type('text/plain').send('Too many requests');
    }
    const sigHeader = req.headers['calendly-webhook-signature'];
    let rawUtf8 =
      Buffer.isBuffer(req.body) ? req.body.toString('utf8') : typeof req.body === 'string' ? req.body : '';
    if (!rawUtf8.length) rawUtf8 = '{}';

    if (!verifyCalendlySignature(rawUtf8, sigHeader)) {
      console.warn('Calendly webhook rejected: bad signature');
      return res.status(403).json({ ok: false, error: 'Invalid signature' });
    }

    let parsedBody;
    try {
      parsedBody = JSON.parse(rawUtf8);
    } catch {
      return res.status(400).json({ ok: false, error: 'Invalid JSON' });
    }

    const ev = String(parsedBody.event || '');
    if (
      ev !== 'invitee.created' &&
      ev !== 'invitee.canceled'
    ) {
      return res.status(204).send();
    }

    const norm = normalizeCalendlyWebhook(parsedBody);
    if (!norm) {
      return res.status(400).json({ ok: false, error: 'Could not normalize' });
    }
    ensureDataDir();
    fs.appendFileSync(CALENDLY_EVENTS_FILE, JSON.stringify(norm) + '\n', 'utf8');

    console.log(`Calendly webhook stored: ${norm.webhookEvent} ${norm.ref}`);
    return res.status(200).json({ ok: true, received: norm.webhookEvent, ref: norm.ref });
  }
);

app.use(express.json({ limit: '128kb' }));

const rootDir = path.join(__dirname, '..');

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function adminSecurityHeaders(_req, res, next) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  next();
}

function requireBearerAdmin(req, res, next) {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({ error: 'Admin access is not configured on this server.' });
  }
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!raw || !secretEquals(ADMIN_TOKEN, raw)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return next();
}

function adminGate(req, res, next) {
  const ip = clientIp(req);
  if (!rateLimitAdmin(ip)) {
    return res.status(429).json({ error: 'Too many admin requests. Try again later.' });
  }
  return next();
}

app.get('/api/health', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ ok: true, service: 'bws-booking-api', time: new Date().toISOString() });
});

app.post('/api/bookings', async (req, res) => {
  try {
    const ip = clientIp(req);
    if (!rateLimitBooking(ip)) {
      return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }

    const body = req.body || {};
    if (String(body.company_website || '').trim() !== '') {
      return res.status(400).json({ error: 'Invalid request.' });
    }

    const {
      service,
      scheduledDate,
      scheduledTime,
      clientTimezone,
      firstName,
      lastName,
      email,
      phone,
      notes,
      goal,
      urgency,
      tools,
      budgetRange,
      consent,
    } = body;

    if (!consent) {
      return res.status(400).json({ error: 'Please accept contact consent to continue.' });
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!service || typeof service !== 'string' || service.length > 200) {
      return res.status(400).json({ error: 'Invalid service.' });
    }
    if (!scheduledDate || !/^\d{4}-\d{2}-\d{2}$/.test(scheduledDate)) {
      return res.status(400).json({ error: 'Invalid date.' });
    }
    if (!scheduledTime || typeof scheduledTime !== 'string' || scheduledTime.length > 40) {
      return res.status(400).json({ error: 'Invalid time.' });
    }
    const fn = String(firstName || '').trim();
    const ln = String(lastName || '').trim();
    const em = String(email || '').trim().toLowerCase();
    if (!fn || !ln || fn.length > 80 || ln.length > 80) {
      return res.status(400).json({ error: 'Please enter your first and last name.' });
    }
    if (!emailRe.test(em)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    const idemKey = (req.headers['idempotency-key'] || body.idempotencyKey || '').trim();
    if (idemKey) {
      ensureDataDir();
      const idem = loadIdempotency();
      const prev = idem[idemKey];
      if (prev && Date.now() - prev.ts < 24 * 60 * 60 * 1000) {
        return res.status(200).json({ ok: true, booking: prev.booking, duplicate: true });
      }
    }

    const [Y, M, D] = scheduledDate.split('-').map(Number);
    const scheduledAtUtc = manilaWallToUtcIso(Y, M - 1, D, scheduledTime);
    if (!scheduledAtUtc) {
      return res.status(400).json({ error: 'Could not parse scheduled time.' });
    }

    const ref = refFromBody();
    const createdAt = new Date().toISOString();
    const booking = {
      ref,
      status: 'pending',
      createdAt,
      service: service.slice(0, 200),
      scheduledDate,
      scheduledTime,
      scheduledAtUtc,
      businessTimezone: BUSINESS_TZ,
      clientTimezone: String(clientTimezone || '').slice(0, 80) || 'unknown',
      firstName: fn,
      lastName: ln,
      email: em,
      phone: String(phone || '').trim().slice(0, 40) || null,
      notes: String(notes || '').trim().slice(0, 4000) || null,
      goal: String(goal || '').trim().slice(0, 500) || null,
      urgency: String(urgency || '').trim().slice(0, 80) || null,
      tools: String(tools || '').trim().slice(0, 500) || null,
      budgetRange: String(budgetRange || '').trim().slice(0, 120) || null,
    };

    ensureDataDir();
    fs.appendFileSync(BOOKINGS_FILE, JSON.stringify(booking) + '\n', 'utf8');

    if (idemKey) {
      const idem = loadIdempotency();
      idem[idemKey] = { ts: Date.now(), booking };
      saveIdempotency(idem);
    }

    const summaryLines = [
      `Ref: ${ref}`,
      `Service: ${booking.service}`,
      `When (office ${BUSINESS_TZ}): ${scheduledDate} ${scheduledTime}`,
      `UTC: ${scheduledAtUtc}`,
      `Client TZ: ${booking.clientTimezone}`,
      `Name: ${fn} ${ln}`,
      `Email: ${em}`,
      `Phone: ${booking.phone || '—'}`,
      `Goal: ${booking.goal || '—'}`,
      `Urgency: ${booking.urgency || '—'}`,
      `Tools: ${booking.tools || '—'}`,
      `Budget: ${booking.budgetRange || '—'}`,
      `Notes: ${booking.notes || '—'}`,
    ].join('\n');

    let emailStatus = { prospect: 'skipped', team: 'skipped' };
    try {
      if (RESEND_API_KEY && RESEND_FROM) {
        const prospectHtml = `<p>Hi ${escapeHtml(fn)},</p>
<p>We received your discovery call request.</p>
<ul>
<li><strong>Reference:</strong> ${escapeHtml(ref)}</li>
<li><strong>Service:</strong> ${escapeHtml(booking.service)}</li>
<li><strong>Requested slot (${escapeHtml(BUSINESS_TZ)}):</strong> ${escapeHtml(scheduledDate)} at ${escapeHtml(scheduledTime)}</li>
<li><strong>Your timezone:</strong> ${escapeHtml(booking.clientTimezone)}</li>
</ul>
<p>Our team will confirm by email or WhatsApp within a few hours on business days.</p>
<p>— Best Work Solution</p>`;
        await sendResend(em, `We received your booking (${ref})`, prospectHtml);
        emailStatus.prospect = 'sent';

        const teamHtml = `<pre style="font-family:system-ui,sans-serif">${escapeHtml(summaryLines)}</pre>`;
        await sendResend(TEAM_NOTIFY_EMAIL, `[BWS] New booking ${ref}`, teamHtml);
        emailStatus.team = 'sent';
      }
    } catch (e) {
      console.error('Resend error:', e.message);
      emailStatus.error = e.message;
    }

    return res.status(201).json({ ok: true, booking, emailStatus });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

function readAllBookings() {
  ensureDataDir();
  if (!fs.existsSync(BOOKINGS_FILE)) return [];
  const lines = fs.readFileSync(BOOKINGS_FILE, 'utf8').split('\n').filter(Boolean);
  const out = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line));
    } catch {
      /* skip */
    }
  }
  return out;
}

app.get(
  '/api/bookings/admin',
  adminSecurityHeaders,
  adminGate,
  requireBearerAdmin,
  (req, res) => {
    const unified = buildUnifiedTimeline();
    const filt = String(req.query.source || '').toLowerCase();
    let rows = unified;
    if (filt === 'website') rows = unified.filter((r) => r.source === 'website');
    if (filt === 'calendly') rows = unified.filter((r) => r.source === 'calendly');
    const metricsDays = Math.min(Number(process.env.METRICS_DAYS) || 14, 90);
    const metrics = aggregateMetrics(metricsDays);
    res.json({
      count: rows.length,
      totalUnified: unified.length,
      unified: rows,
      metrics,
    });
  }
);

app.get(
  '/api/admin/metrics',
  adminSecurityHeaders,
  adminGate,
  requireBearerAdmin,
  (_req, res) => {
    const days = Math.min(Number(process.env.METRICS_DAYS) || 14, 90);
    res.json(aggregateMetrics(days));
  }
);

app.get(
  '/api/bookings/export.csv',
  adminSecurityHeaders,
  adminGate,
  requireBearerAdmin,
  (req, res) => {
    const raw = String(req.query.raw || '').toLowerCase();
    if (raw === 'website') {
      const rows = readAllBookings();
      const headers = [
        'ref',
        'status',
        'createdAt',
        'service',
        'scheduledDate',
        'scheduledTime',
        'scheduledAtUtc',
        'clientTimezone',
        'firstName',
        'lastName',
        'email',
        'phone',
        'goal',
        'urgency',
        'tools',
        'budgetRange',
        'notes',
      ];
      const esc = (v) => {
        const s = v == null ? '' : String(v);
        if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
        return s;
      };
      const lines = [headers.join(',')];
      for (const b of rows) {
        lines.push(headers.map((h) => esc(b[h])).join(','));
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="bws-website-bookings.csv"');
      return res.send(lines.join('\n'));
    }

    const unified = [...buildUnifiedTimeline()].reverse();
    const headers = [
      'source',
      'ref',
      'createdAt',
      'status',
      'detail',
      'email',
      'firstName',
      'lastName',
      'scheduledAtUtcOrComposite',
      'phone',
      'inviteeUri',
      'notesOrEventUri',
    ];
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    };
    const lines = [headers.join(',')];
    for (const r of unified) {
      const detail = r.webhookEventOrService || '';
      const composite =
        r.scheduledDate && r.scheduledTime
          ? `${r.scheduledDate} ${r.scheduledTime}`
          : r.scheduledAtUtc || '';
      const rowObj = {
        source: r.source,
        ref: r.ref,
        createdAt: r.createdAt,
        status: r.status,
        detail,
        email: r.email || '',
        firstName: r.firstName || '',
        lastName: r.lastName || '',
        scheduledAtUtcOrComposite: composite,
        phone: r.phone || '',
        inviteeUri: r.inviteeUri || '',
        notesOrEventUri: r.eventNote || '',
      };
      lines.push(headers.map((h) => esc(rowObj[h])).join(','));
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="bws-appointments-unified.csv"');
    res.send(lines.join('\n'));
  }
);

app.get('/admin', optionalBasicAuthAdminShell, adminSecurityHeaders, (_req, res) => {
  res.redirect(302, '/admin/bookings.html');
});

app.get('/admin/bookings.html', optionalBasicAuthAdminShell, adminSecurityHeaders, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-bookings.html'));
});

app.use(
  '/admin',
  optionalBasicAuthAdminShell,
  adminSecurityHeaders,
  express.static(path.join(__dirname, 'public'), {
    index: false,
    dotfiles: 'deny',
    fallthrough: true,
  })
);

app.use(express.static(rootDir));

ensureDataDir();
app.listen(PORT, () => {
  console.log(`BWS server listening on port ${PORT}`);
  console.log(`Health: /api/health`);
  console.log(`Admin UI: /admin/bookings.html`);
  if (IS_PROD && !ALLOWED_ORIGINS.length) {
    console.warn('WARN: ALLOWED_ORIGINS is empty in production — cross-origin booking POSTs will be blocked by the browser. Set ALLOWED_ORIGINS to your public site URL(s).');
  }
  if (!ADMIN_TOKEN) console.warn('WARN: ADMIN_TOKEN not set — admin API disabled until configured.');
  if (!ADMIN_BASIC_USER) {
    console.warn('WARN: ADMIN_BASIC_USER / ADMIN_BASIC_PASS not set — optional first login wall for /admin pages only.');
  }
});
