import express from 'express';
import cors from 'cors';
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
const IDEMPOTENCY_FILE = path.join(DATA_DIR, 'idempotency.json');

const PORT = Number(process.env.PORT) || 3847;
const BUSINESS_TZ = process.env.BUSINESS_TZ || 'Asia/Manila';
const TEAM_NOTIFY_EMAIL = process.env.TEAM_NOTIFY_EMAIL || 'bestworkssolutions@gmail.com';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM = process.env.RESEND_FROM || '';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX = 8;
const ipHits = new Map();

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

function rateLimit(ip) {
  const now = Date.now();
  let arr = ipHits.get(ip) || [];
  arr = arr.filter((t) => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) return false;
  arr.push(now);
  ipHits.set(ip, arr);
  return true;
}

function parseTimeTo24(hm, ampm) {
  let [h, m] = hm.split(':').map(Number);
  if (ampm === 'PM' && h !== 12) h += 12;
  if (ampm === 'AM' && h === 12) h = 0;
  return { h, m: m || 0 };
}

/** Build ISO instant for office wall-clock in Manila (+08:00). */
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
app.use(
  cors({
    origin: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Idempotency-Key'],
  })
);
app.use(express.json({ limit: '128kb' }));

const rootDir = path.join(__dirname, '..');

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

app.post('/api/bookings', async (req, res) => {
  try {
    const ip = clientIp(req);
    if (!rateLimit(ip)) {
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
        await sendResend(
          em,
          `We received your booking (${ref})`,
          prospectHtml
        );
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

function requireAdmin(req, res, next) {
  const token = req.query.token || req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/api/bookings/admin', requireAdmin, (req, res) => {
  const bookings = readAllBookings().reverse();
  res.json({ count: bookings.length, bookings });
});

app.get('/api/bookings/export.csv', requireAdmin, (req, res) => {
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
  res.setHeader('Content-Disposition', 'attachment; filename="bws-bookings.csv"');
  res.send(lines.join('\n'));
});

app.get('/admin/bookings.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-bookings.html'));
});

app.use(express.static(rootDir));

ensureDataDir();
app.listen(PORT, () => {
  console.log(`BWS server http://localhost:${PORT}`);
  console.log(`Open site: http://localhost:${PORT}/test/index.html`);
  if (!ADMIN_TOKEN) console.warn('WARN: ADMIN_TOKEN not set — admin API disabled until configured.');
});
