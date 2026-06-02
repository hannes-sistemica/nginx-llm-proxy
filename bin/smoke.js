#!/usr/bin/env node
// Smoke gate: validate every registered model through the proxy with the
// CORRECT methodology — no max_tokens, thinking disabled, PASS only on
// HTTP 200 + non-empty content (chat) or a real vector (embeddings).
// Multi-backend chat models are tested auto-routed AND per-backend (a healthy
// backend that returns empty is a FAIL; a health=down backend is skipped, since
// the proxy correctly fails over). Exits non-zero if anything fails — so it can
// gate a deploy. Encodes the "assume the worst, empty=broken" rule.
const PROXY = process.env.PROXY_URL || 'http://192.168.1.125:4000';
const ADMIN = process.env.ADMIN_PASSWORD || '';
const KEY   = process.env.API_KEY || ADMIN || 'sk-1234';
const TIMEOUT = Number(process.env.SMOKE_TIMEOUT || 120000);

const isEmbed = n => /embed|nomic/i.test(n);

// Retry once on failure so a transient blip (a backend mid-restart) doesn't
// fail the gate; a persistent failure still fails twice.
async function retry(fn) {
  let r = await fn();
  if (!r.ok) { await new Promise(s => setTimeout(s, 800)); r = await fn(); }
  return r;
}

async function post(path, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const r = await fetch(PROXY + path, {
      method: 'POST', signal: ctrl.signal,
      headers: { 'Authorization': 'Bearer ' + KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => null);
    return { code: r.status, j };
  } catch (e) {
    return { code: 'ERR', err: String(e.message || e) };
  } finally { clearTimeout(t); }
}

async function chat(model) {
  const { code, j, err } = await post('/v1/chat/completions', {
    model, messages: [{ role: 'user', content: 'Reply with exactly one word: ok' }],
    chat_template_kwargs: { enable_thinking: false },
  });
  if (err) return { ok: false, code: 'ERR', detail: err.slice(0, 50) };
  let c = (j?.choices?.[0]?.message?.content || '').replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  return { ok: code === 200 && c.length > 0, code,
    detail: c.length ? JSON.stringify(c).slice(0, 30) : (j?.error ? JSON.stringify(j.error).slice(0, 60) : 'EMPTY content') };
}

async function embed(model) {
  const { code, j, err } = await post('/v1/embeddings', { model, input: 'smoke test' });
  if (err) return { ok: false, code: 'ERR', detail: err.slice(0, 50) };
  const v = j?.data?.[0]?.embedding;
  return { ok: code === 200 && Array.isArray(v) && v.length > 0, code,
    detail: Array.isArray(v) ? `dim ${v.length}` : (j?.error ? JSON.stringify(j.error).slice(0, 60) : 'no vector') };
}

async function getJSON(path) {
  const r = await fetch(PROXY + path, { headers: { 'X-Admin-Password': ADMIN } });
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status} (check ADMIN_PASSWORD)`);
  return r.json();
}

(async () => {
  const mj = await getJSON('/admin/api/models');
  const raw = mj.models || mj;
  const models = Array.isArray(raw) ? raw : Object.entries(raw).map(([name, v]) => ({ name, ...v }));
  const hj = await getJSON('/admin/api/health').catch(() => ({ backends: {} }));
  const statusOf = url => hj.backends?.[url]?.status;

  let fails = 0, total = 0;
  const rows = [];
  const record = (icon, name, route, code, detail) => rows.push([icon, name + ' ' + route, String(code), detail]);

  for (const m of models) {
    const name = m.name;
    if (isEmbed(name)) {
      const r = await retry(() => embed(name)); total++; if (!r.ok) fails++;
      record(r.ok ? '✅' : '❌', name, '(embed)', r.code, r.detail);
      continue;
    }
    const backends = (m.backends && m.backends.length) ? m.backends : null;
    // auto-routed (the user-facing contract — must pass)
    const ra = await retry(() => chat(name)); total++; if (!ra.ok) fails++;
    record(ra.ok ? '✅' : '❌', name, 'auto', ra.code, ra.detail);
    // each backend (catch a healthy-but-broken backend hiding behind failover)
    if (backends && backends.length > 1) {
      for (const b of backends) {
        if (statusOf(b.url) === 'down') { record('⏭️', name, '@' + b.name, 'down', 'skipped (health=down)'); continue; }
        const r = await retry(() => chat(name + '@' + b.name)); total++; if (!r.ok) fails++;
        record(r.ok ? '✅' : '❌', name, '@' + b.name, r.code, r.detail);
      }
    }
  }

  for (const r of rows) console.log(r[0].padEnd(2), r[1].padEnd(32), r[2].padEnd(5), r[3]);
  console.log(`\n${total - fails}/${total} passed` + (fails ? `  — ${fails} FAILED` : ' ✓'));
  process.exit(fails > 0 ? 1 : 0);
})().catch(e => { console.error('smoke error:', e.message); process.exit(2); });
