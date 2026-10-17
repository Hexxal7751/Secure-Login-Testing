/* Secure Login Testing — UI behaviour
   Loaded as an external file (allowed by CSP 'self').
   Backend endpoints/fields are untouched; this only drives the UI. */
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const csrf = document.body.dataset.csrf || '';
  const fine = matchMedia('(pointer: fine)').matches;
  const wait = ms => new Promise(r => setTimeout(r, ms));

  /* ---------- Toasts ---------- */
  const ICON = t => (['danger', 'error', 'warning'].includes(t) ? 'alert' : t === 'success' ? 'check' : 'info');
  function toast(msg, type = 'info') {
    const box = $('.toasts'); if (!box) return;
    const el = document.createElement('div');
    el.className = 't-' + type + ' toast'; el.setAttribute('role', 'alert');
    el.innerHTML = '<span class="t-ic"><svg class="ic"><use href="#i-' + ICON(type) + '"/></svg></span><p></p>' +
      '<button type="button" class="t-x" data-toast-close aria-label="Dismiss"><svg class="ic"><use href="#i-x"/></svg></button>';
    $('p', el).textContent = msg; box.appendChild(el);
    setTimeout(() => el.remove(), 7200);
  }
  document.addEventListener('click', e => {
    const x = e.target.closest('[data-toast-close]'); if (!x) return;
    const t = x.closest('.toast'); t.classList.add('out'); setTimeout(() => t.remove(), 400);
  });

  /* ---------- Particle network background ---------- */
  function particles() {
    const cv = $('#fx'); if (!cv || reduce) return;
    const ctx = cv.getContext('2d'); let w, h, dpr, pts = [], mx = -9999, my = -9999, run = true;
    const make = () => {
      dpr = Math.min(devicePixelRatio || 1, 2); w = cv.width = innerWidth * dpr; h = cv.height = innerHeight * dpr;
      const n = Math.min(80, Math.floor(innerWidth * innerHeight / 20000));
      pts = Array.from({ length: n }, () => ({
        x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .4 * dpr, vy: (Math.random() - .5) * .4 * dpr,
        r: (Math.random() * 1.5 + .6) * dpr, c: Math.random() < .5 ? '168,85,247' : '56,189,248'
      }));
    };
    const frame = () => {
      if (!run) return; ctx.clearRect(0, 0, w, h); const D = 150 * dpr;
      for (let i = 0; i < pts.length; i++) {
        const p = pts[i]; p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.283); ctx.fillStyle = 'rgba(' + p.c + ',.85)'; ctx.fill();
        for (let j = i + 1; j < pts.length; j++) {
          const q = pts[j], d = Math.hypot(p.x - q.x, p.y - q.y);
          if (d < D) { ctx.strokeStyle = 'rgba(' + p.c + ',' + (.22 * (1 - d / D)) + ')'; ctx.lineWidth = dpr * .8; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke(); }
        }
        const dm = Math.hypot(p.x - mx, p.y - my);
        if (dm < D * 1.3) { ctx.strokeStyle = 'rgba(217,70,239,' + (.45 * (1 - dm / (D * 1.3))) + ')'; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(mx, my); ctx.stroke(); p.x += (mx - p.x) * .003; p.y += (my - p.y) * .003; }
      }
      requestAnimationFrame(frame);
    };
    make(); frame();
    addEventListener('resize', make);
    addEventListener('pointermove', e => { mx = e.clientX * dpr; my = e.clientY * dpr; }, { passive: true });
    document.addEventListener('visibilitychange', () => { run = !document.hidden; if (run) frame(); });
  }

  /* ---------- Cursor glow, tilt, magnetic buttons ---------- */
  function pointerFx() {
    const glow = $('.cursor-glow');
    if (glow && fine && !reduce) {
      addEventListener('pointermove', e => { glow.classList.add('on'); glow.style.transform = 'translate(' + e.clientX + 'px,' + e.clientY + 'px)'; }, { passive: true });
      document.addEventListener('pointerleave', () => glow.classList.remove('on'));
    }
    $$('[data-tilt]').forEach(el => {
      const amt = parseFloat(el.dataset.tilt) || 6;
      el.addEventListener('pointermove', e => {
        if (e.pointerType === 'touch') return;
        const r = el.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
        el.style.setProperty('--mx', x * 100 + '%'); el.style.setProperty('--my', y * 100 + '%');
        if (!reduce) { el.style.setProperty('--ry', (x - .5) * amt + 'deg'); el.style.setProperty('--rx', (.5 - y) * amt + 'deg'); }
      });
      el.addEventListener('pointerleave', () => { el.style.setProperty('--rx', '0deg'); el.style.setProperty('--ry', '0deg'); });
    });
    if (fine && !reduce) $$('.btn').forEach(b => {
      b.addEventListener('pointermove', e => {
        const r = b.getBoundingClientRect(); b.style.translate = (e.clientX - r.left - r.width / 2) * .08 + 'px ' + (e.clientY - r.top - r.height / 2) * .18 + 'px';
      });
      b.addEventListener('pointerleave', () => { b.style.translate = ''; });
    });
  }

  /* ---------- Button ripple ---------- */
  document.addEventListener('click', e => {
    const b = e.target.closest('.btn'); if (!b || reduce) return;
    const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height), sp = document.createElement('span');
    sp.className = 'ripple'; sp.style.width = sp.style.height = s + 'px';
    sp.style.left = e.clientX - r.left - s / 2 + 'px'; sp.style.top = e.clientY - r.top - s / 2 + 'px';
    b.appendChild(sp); setTimeout(() => sp.remove(), 750);
  });

  /* ---------- Split-text headline ---------- */
  $$('[data-split]').forEach(el => {
    const t = el.textContent.trim(); el.setAttribute('aria-label', t); el.textContent = ''; let k = 0;
    t.split(' ').forEach((word, wi, arr) => {
      const w = document.createElement('span'); w.className = 'w'; w.setAttribute('aria-hidden', 'true');
      [...word].forEach(c => { const s = document.createElement('span'); s.className = 'ch'; s.textContent = c; s.style.setProperty('--k', k++); w.appendChild(s); });
      el.appendChild(w); if (wi < arr.length - 1) el.appendChild(document.createTextNode(' '));
    });
  });

  /* ---------- Scroll reveal + count-up ---------- */
  function countUp(el) {
    const to = parseFloat(el.dataset.count) || 0, dur = 1400, t0 = performance.now();
    if (reduce) { el.textContent = to; return; }
    const tick = t => { const p = Math.min(1, (t - t0) / dur); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  }
  const io = new IntersectionObserver(es => es.forEach(en => {
    if (!en.isIntersecting) return; en.target.classList.add('in');
    $$('[data-count]', en.target).forEach(countUp); io.unobserve(en.target);
  }), { threshold: .2 });
  $$('.reveal').forEach((el, i) => { el.style.setProperty('--d', i % 6); io.observe(el); });

  /* ---------- Stepper ---------- */
  $$('.stepper').forEach(s => setTimeout(() => s.classList.add('go'), 400));

  /* ---------- Modals ---------- */
  let lastFocus = null;
  const openModal = id => {
    const m = document.getElementById(id); if (!m) return; lastFocus = document.activeElement;
    m.classList.add('open'); m.setAttribute('aria-hidden', 'false');
    setTimeout(() => ($('[data-close]', m) || m).focus(), 60);
  };
  const closeModal = m => { m.classList.remove('open'); m.setAttribute('aria-hidden', 'true'); if (lastFocus) lastFocus.focus(); };
  document.addEventListener('click', e => {
    const o = e.target.closest('[data-open]'); if (o) { e.preventDefault(); openModal(o.dataset.open); return; }
    const c = e.target.closest('[data-close]'); if (c) { closeModal(c.closest('.modal')); return; }
    if (e.target.classList.contains('modal')) closeModal(e.target);
  });
  addEventListener('keydown', e => { if (e.key === 'Escape') $$('.modal.open').forEach(closeModal); });

  /* ---------- Form submit → loading state ---------- */
  $$('form').forEach(f => f.addEventListener('submit', e => {
    if (f.dataset.busy) { e.preventDefault(); return; }
    f.dataset.busy = '1'; const b = $('button[type=submit]', f); if (b) b.classList.add('loading');
  }));
  addEventListener('pageshow', () => {   // back/forward cache: reset
    $$('form').forEach(f => { delete f.dataset.busy; }); $$('.btn.loading').forEach(b => b.classList.remove('loading'));
    document.body.classList.remove('leaving');
  });

  /* ---------- Page-leave transition for internal links ---------- */
  document.addEventListener('click', e => {
    const a = e.target.closest('a[href]'); if (!a || reduce) return;
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button || a.target || a.hasAttribute('download')) return;
    const u = new URL(a.href, location.href); if (u.origin !== location.origin || u.href === location.href) return;
    e.preventDefault(); document.body.classList.add('leaving'); setTimeout(() => { location.href = u.href; }, 260);
  });

  /* ---------- Password: toggle, caps lock, strength ---------- */
  $$('[data-toggle-pw]').forEach(b => b.addEventListener('click', () => {
    const i = $('input', b.closest('.field')), show = i.type === 'password';
    i.type = show ? 'text' : 'password'; b.setAttribute('aria-pressed', String(show)); b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  }));
  $$('input[type=password]').forEach(i => {
    const hint = $('[data-caps]', i.closest('form') || document);
    const chk = e => { if (hint && e.getModifierState) hint.classList.toggle('on', e.getModifierState('CapsLock')); };
    i.addEventListener('keydown', chk); i.addEventListener('keyup', chk); i.addEventListener('blur', () => hint && hint.classList.remove('on'));
  });
  const meter = $('[data-meter]'), pwIn = $('#password[data-strength]');
  if (meter && pwIn) {
    const label = $('[data-meter-label]'), words = ['Use at least 8 characters', 'Weak', 'Okay', 'Good', 'Strong'];
    pwIn.addEventListener('input', () => {
      const v = pwIn.value; let s = 0;
      if (v.length >= 8) s++; if (v.length >= 12) s++; if (/[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v)) s++; if (/[^A-Za-z0-9]/.test(v) && v.length >= 8) s++;
      if (!v) s = 0; meter.dataset.s = s; if (label) label.textContent = v ? words[Math.max(s, 1)] : words[0];
    });
  }

  /* ---------- Username availability (uses existing /check-username/<u>) ---------- */
  const un = $('#username[data-check]');
  if (un) {
    const field = un.closest('.field'), hint = $('[data-user-hint]'), tpl = un.dataset.check, cache = {}; let timer, seq = 0;
    const RE = /^[a-zA-Z0-9_]{3,20}$/;
    const set = (st, msg, cls) => { if (st) field.dataset.state = st; else delete field.dataset.state; field.classList.toggle('ok', st === 'ok'); field.classList.toggle('bad', st === 'bad'); if (hint) { hint.textContent = msg; hint.className = 'hint ' + (cls || ''); } };
    un.addEventListener('input', () => {
      clearTimeout(timer); const v = un.value.trim(); const my = ++seq;
      if (!v) return set(null, '3–20 characters: letters, numbers and underscores.', '');
      if (!RE.test(v)) return set('bad', 'Use 3–20 letters, numbers or underscores.', 'bad');
      if (v in cache) return set(cache[v] ? 'ok' : 'bad', cache[v] ? 'Nice — that username is free.' : 'That username is already taken.', cache[v] ? 'ok' : 'bad');
      set('checking', 'Checking availability…', '');
      timer = setTimeout(async () => {
        try {
          const r = await fetch(tpl.replace('USERNAME', encodeURIComponent(v)), { credentials: 'same-origin' });
          const j = await r.json(); if (my !== seq) return; cache[v] = !!j.available;
          set(j.available ? 'ok' : 'bad', j.available ? 'Nice — that username is free.' : (j.reason === 'invalid_format' ? 'Use 3–20 letters, numbers or underscores.' : 'That username is already taken.'), j.available ? 'ok' : 'bad');
        } catch (_) { if (my === seq) set(null, '', ''); }
      }, 500);
    });
  }

  /* ---------- Six-box one-time code ---------- */
  $$('[data-otp]').forEach(root => {
    const form = root.closest('form'), hidden = $('input[name=totp_code]', form), boxes = $$('input', root);
    const sync = () => (hidden.value = boxes.map(b => b.value).join(''));
    const fill = (txt, from = 0) => {
      const d = txt.replace(/\D/g, '').slice(0, 6 - from); [...d].forEach((c, k) => { boxes[from + k].value = c; boxes[from + k].classList.add('filled'); });
      boxes[Math.min(from + d.length, 5)].focus(); if (sync().length === 6) done();
    };
    const done = () => { root.classList.add('complete'); setTimeout(() => (form.requestSubmit ? form.requestSubmit() : form.submit()), 550); };
    boxes.forEach((b, i) => {
      b.addEventListener('input', () => {
        if (b.value.length > 1) { fill(b.value, i); return; }     // OS autofill / fast typing
        b.value = b.value.replace(/\D/g, ''); b.classList.toggle('filled', !!b.value);
        if (b.value && i < 5) boxes[i + 1].focus(); if (sync().length === 6) done();
      });
      b.addEventListener('keydown', e => {
        if (e.key === 'Backspace' && !b.value && i > 0) { boxes[i - 1].value = ''; boxes[i - 1].classList.remove('filled'); boxes[i - 1].focus(); sync(); }
        else if (e.key === 'ArrowLeft' && i > 0) boxes[i - 1].focus();
        else if (e.key === 'ArrowRight' && i < 5) boxes[i + 1].focus();
      });
      b.addEventListener('paste', e => { e.preventDefault(); fill((e.clipboardData || window.clipboardData).getData('text'), 0); });
      b.addEventListener('focus', () => b.select());
    });
    boxes[0].focus();
  });

  /* ---------- 30-second TOTP countdown ring ---------- */
  $$('[data-ring]').forEach(r => {
    const fg = $('.fg', r), num = $('.num', r), L = 2 * Math.PI * 18; fg.style.strokeDasharray = L;
    const tick = () => { const s = 30 - (Date.now() / 1000 % 30); fg.style.strokeDashoffset = L * (1 - s / 30); num.textContent = Math.ceil(s); r.classList.toggle('low', s < 6); };
    tick(); setInterval(tick, 250);
  });

  /* ---------- Copy + secret reveal ---------- */
  $$('[data-copy]').forEach(b => b.addEventListener('click', async () => {
    const src = $(b.dataset.copy); if (!src) return; const txt = src.textContent.trim();
    try { await navigator.clipboard.writeText(txt); } catch (_) { const r = document.createRange(); r.selectNodeContents(src); const s = getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand('copy'); s.removeAllRanges(); }
    const lbl = $('span', b), old = lbl.textContent; b.classList.add('done'); lbl.textContent = 'Copied'; toast('Secret key copied to clipboard.', 'success');
    setTimeout(() => { b.classList.remove('done'); lbl.textContent = old; }, 1800);
  }));
  $$('.secret code').forEach(c => c.addEventListener('click', () => c.closest('.secret').classList.toggle('show')));

  /* ---------- Passkeys (WebAuthn) ---------- */
  const b64u = {
    enc: buf => { let s = ''; new Uint8Array(buf).forEach(c => (s += String.fromCharCode(c))); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    dec: str => { str = str.replace(/-/g, '+').replace(/_/g, '/'); str += '='.repeat((4 - str.length % 4) % 4); const bin = atob(str), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; }
  };
  async function post(url, body) {
    const r = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify(body || {}) });
    let j = {}; try { j = await r.json(); } catch (_) { }
    if (r.status === 429) throw new Error('Too many attempts. Wait a minute and try again.');
    if (!r.ok || j.error) throw new Error(j.error || 'Request failed (' + r.status + ').');
    return j;
  }
  async function registerPasskey(d) {
    const pk = (await post(d.begin)).publicKey;
    pk.challenge = b64u.dec(pk.challenge); pk.user.id = b64u.dec(pk.user.id);
    (pk.excludeCredentials || []).forEach(c => (c.id = b64u.dec(c.id)));
    const cred = await navigator.credentials.create({ publicKey: pk }), r = cred.response;
    await post(d.complete, { id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, response: { clientDataJSON: b64u.enc(r.clientDataJSON), attestationObject: b64u.enc(r.attestationObject) } });
    return d.next;
  }
  async function authPasskey(d) {
    const pk = (await post(d.begin)).publicKey;
    pk.challenge = b64u.dec(pk.challenge); (pk.allowCredentials || []).forEach(c => (c.id = b64u.dec(c.id)));
    const cred = await navigator.credentials.get({ publicKey: pk }), r = cred.response;
    const j = await post(d.complete, {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      response: { authenticatorData: b64u.enc(r.authenticatorData), clientDataJSON: b64u.enc(r.clientDataJSON), signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null }
    });
    return j.redirect;
  }
  $$('[data-passkey]').forEach(root => {
    const d = root.dataset, orb = $('.orb', root), status = $('.status', root), btn = $('[data-pk-go]', root);
    const set = (state, msg) => { orb.dataset.state = state; status.className = 'status ' + state; status.textContent = msg; };
    if (!window.PublicKeyCredential) { set('err', 'This browser does not support passkeys.'); btn.disabled = true; return; }
    btn.addEventListener('click', async () => {
      btn.classList.add('loading'); set('wait', d.mode === 'register' ? 'Waiting for your device…' : 'Confirm with your passkey…');
      try {
        const dest = await (d.mode === 'register' ? registerPasskey(d) : authPasskey(d));
        set('ok', d.mode === 'register' ? 'Passkey created. Verifying…' : 'Verified. Opening your dashboard…');
        await wait(1000); document.body.classList.add('leaving'); location.href = dest;
      } catch (err) {
        btn.classList.remove('loading');
        const m = err && err.name === 'NotAllowedError' ? 'Cancelled or timed out. Try again when you are ready.' : (err && err.name === 'InvalidStateError' ? 'This device already has a passkey for this account.' : (err.message || 'Something went wrong.'));
        set('err', m); toast(m, 'error');
      }
    });
  });

  /* ---------- Session countdown (dashboard) ---------- */
  const sess = $('[data-session]');
  if (sess) {
    const fg = $('.fg', sess), num = $('.num', sess), L = 2 * Math.PI * 18, total = +sess.dataset.session || 1800, ping = sess.dataset.ping;
    let end = Date.now() + total * 1000, left = total, warned = false; fg.style.strokeDasharray = L;
    const draw = () => {
      const m = Math.floor(left / 60), s = left % 60; num.textContent = m + ':' + String(s).padStart(2, '0');
      fg.style.strokeDashoffset = L * (1 - left / total); sess.classList.toggle('low', left < 300);
    };
    draw();
    setInterval(() => {
      const prev = left; left = Math.max(0, Math.round((end - Date.now()) / 1000)); if (left === prev) return;
      draw();
      if (left <= 300 && left > 0 && !warned) { warned = true; toast('Your session expires in 5 minutes. Use “Extend session” to stay signed in.', 'warning'); }
      if (left === 0) openModal('expired');
    }, 500);
    $$('[data-extend]').forEach(b => b.addEventListener('click', async () => {
      b.classList.add('loading');
      try { const r = await fetch(ping, { credentials: 'same-origin' }); if (!r.ok || r.redirected) throw 0; end = Date.now() + total * 1000; left = total; warned = false; draw(); toast('Session extended for another 30 minutes.', 'success'); }
      catch (_) { toast('Could not extend the session. Please sign in again.', 'error'); }
      b.classList.remove('loading');
    }));
  }

  particles(); pointerFx();
  window.SL = { toast };
})();
