/* global document */
(function () {
  function authHeaders(token) {
    return {
      Authorization: 'Bearer ' + token,
      Accept: 'application/json',
    };
  }

  function escapeCell(v) {
    if (v == null) return '';
    return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  document.getElementById('load').addEventListener('click', async function () {
    const token = document.getElementById('tok').value.trim();
    const err = document.getElementById('err');
    const out = document.getElementById('out');
    const csvBtn = document.getElementById('csvBtn');
    err.textContent = '';
    out.innerHTML = '';
    csvBtn.style.display = 'none';
    csvBtn.onclick = null;
    if (!token) {
      err.textContent = 'Enter your admin token.';
      return;
    }
    try {
      const r = await fetch('/api/bookings/admin', {
        method: 'GET',
        credentials: 'same-origin',
        headers: authHeaders(token),
      });
      const j = await r.json().catch(function () {
        return {};
      });
      if (!r.ok) {
        err.textContent = j.error || r.statusText || 'Request failed';
        return;
      }
      csvBtn.style.display = 'inline-block';
      csvBtn.onclick = async function () {
        err.textContent = '';
        try {
          const r2 = await fetch('/api/bookings/export.csv', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
              Authorization: 'Bearer ' + token,
              Accept: 'text/csv',
            },
          });
          if (!r2.ok) {
            const t = await r2.text();
            err.textContent = t || r2.statusText;
            return;
          }
          const blob = await r2.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'bws-bookings.csv';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        } catch (e2) {
          err.textContent = String(e2.message);
        }
      };
      const rows = j.bookings || [];
      if (!rows.length) {
        out.textContent = 'No bookings yet.';
        return;
      }
      const cols = [
        'ref',
        'createdAt',
        'status',
        'service',
        'scheduledDate',
        'scheduledTime',
        'scheduledAtUtc',
        'email',
        'firstName',
        'lastName',
        'goal',
        'urgency',
      ];
      let html = '<table><tr>';
      for (let i = 0; i < cols.length; i++) html += '<th>' + escapeCell(cols[i]) + '</th>';
      html += '</tr>';
      for (let ri = 0; ri < rows.length; ri++) {
        const b = rows[ri];
        html += '<tr>';
        for (let c = 0; c < cols.length; c++) {
          html += '<td>' + escapeCell(b[cols[c]]) + '</td>';
        }
        html += '</tr>';
      }
      html += '</table>';
      out.innerHTML = html;
    } catch (e) {
      err.textContent = String(e.message);
    }
  });
})();
