const app = document.getElementById('app');
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_SHORT = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
const ACTIVE = ['queued', 'running', 'paused'];
const TABS = [
  ['authorization', 'authorization'],
  ['target', 'target'],
  ['accounts', 'accounts'],
  ['controls', 'controls'],
  ['scans', 'scans'],
  ['settings', 'settings'],
];
let meta = null;
let me = null; // the signed-in user
let authInfo = null;
let afterLogin = '#/';
let pollTimer = null;
let view = { name: 'home' };
const openState = { selected: null, filter: null };
const visibleFindings = (s) => (openState.filter ? s.findings.filter((f) => f.severity === openState.filter) : s.findings);

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
// Same format as the server-rendered report (src/report.js).
const fmtTime = (iso) => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }) : '—');
/** "30 Oct 2026, 00:49–00:50 GMT+5:30" for same-day ranges; full dates otherwise. */
const fmtRange = (a, b) => {
  if (!b) return fmtDate(a);
  const d1 = new Date(a);
  const d2 = new Date(b);
  if (d1.toDateString() !== d2.toDateString()) return `${fmtDate(a)} → ${fmtDate(b)}`;
  const day = d1.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  return `${day}, ${fmtTime(a)}–${fmtTime(b)} ${fmtDate(b).split(' ').pop()}`;
};
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'project';
const toLocalInput = (iso) => {
  if (!iso) return '';
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};
const fromLocalInput = (v) => (v ? new Date(v).toISOString() : null);
const lines = (text) => String(text || '').split('\n').map((s) => s.trim()).filter(Boolean);
const tag = (sev) => `<span class="tag t-${esc(sev)}">[${esc((SEV_SHORT[sev] || sev).padEnd(4, ' '))}]</span>`;
const status = (s) => `<span class="st st-${esc(s)}">${esc(s)}</span>`;

class AuthError extends Error {}

async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json', 'x-breakapi': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401 && !url.startsWith('/api/auth/') && !url.startsWith('/api/confirm/')) {
    me = null;
    if (!location.hash.startsWith('#/login')) afterLogin = location.hash || '#/';
    location.hash = '#/login';
    throw new AuthError('Sign in required');
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(message, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = isError ? 'error' : '';
  el.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { el.hidden = true; }, isError ? 7000 : 2600);
}

/** In-app confirmation (replaces window.confirm, which breaks the world at the highest-stakes moments). */
function confirmDialog(text, yesLabel = 'Confirm') {
  const d = document.getElementById('confirm-dialog');
  document.getElementById('confirm-text').textContent = text;
  const yes = document.getElementById('confirm-yes');
  const no = document.getElementById('confirm-no');
  yes.textContent = yesLabel;
  return new Promise((resolve) => {
    const done = (v) => {
      d.close();
      resolve(v);
    };
    yes.onclick = () => done(true);
    no.onclick = () => done(false);
    d.oncancel = (e) => {
      e.preventDefault();
      done(false);
    };
    d.showModal();
    no.focus();
  });
}

/** Runs an async UI action, disabling the trigger while it runs and reporting errors as a toast. */
async function act(fn, success, trigger) {
  if (trigger) {
    trigger.disabled = true;
    trigger.setAttribute('aria-busy', 'true');
  }
  const form = trigger?.closest?.('form');
  try {
    const result = await fn();
    if (form) showFormError(form, '');
    if (success) toast(success);
    return result;
  } catch (err) {
    if (!(err instanceof AuthError)) {
      // Errors from a form also appear inside it, next to its submit button, not only in a toast.
      if (form) showFormError(form, err.message);
      toast(err.message, true);
    }
    return undefined;
  } finally {
    if (trigger?.isConnected) {
      trigger.disabled = false;
      trigger.removeAttribute('aria-busy');
    }
  }
}

function showFormError(form, message) {
  let box = form.querySelector(':scope > .form-error');
  if (!message) {
    box?.remove();
    return;
  }
  if (!box) {
    box = document.createElement('p');
    box.className = 'note bad form-error';
    box.setAttribute('role', 'alert');
    const submit = form.querySelector('button[type="submit"]');
    const row = submit?.closest('.cmd') && submit.closest('.cmd').parentElement === form ? submit.closest('.cmd') : submit;
    if (row && row.parentElement === form) form.insertBefore(box, row);
    else form.append(box);
  }
  box.textContent = message;
}

function formValues(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === 'checkbox') out[el.name] = el.checked;
    else if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; } else out[el.name] = el.value;
  }
  return out;
}

function onSubmit(form, handler) {
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    handler(formValues(form), form.querySelector('button[type="submit"], button:not([type])'));
  });
}

// ---------- Shell: prompt path + tmux bar ----------

function setShell({ path = [], windows = null, session = 'breakapi', right = '' }) {
  // On narrow screens the middle segments collapse to an ellipsis so the current location stays visible.
  const parts = path.map((p, i) => {
    if (i === path.length - 1) {
      const sep = i === 0 ? '' : `<span class="sep mid-sep">/</span>${path.length > 1 ? '<span class="ell">…/</span>' : ''}`;
      return `${sep}<span class="here" aria-current="location">${esc(p.label)}</span>`;
    }
    return `${i === 0 ? '' : '<span class="sep mid-sep">/</span>'}<a href="${esc(p.href)}" class="mid">${esc(p.label)}</a>`;
  }).join('');
  document.getElementById('path').innerHTML = `<span class="who">${esc((me?.email || 'guest').split('@')[0])}@breakapi</span><span class="sep">:</span><a href="#/">~</a>${path.length ? '<span class="sep">/</span>' : ''}${parts}<span class="sep">$</span><span class="caret" aria-hidden="true"></span>`;

  const bar = document.getElementById('tmux');
  bar.hidden = false;
  document.getElementById('tmux-session').textContent = `[${session}]`;
  document.getElementById('tmux-windows').innerHTML = (windows || [{ n: 0, label: 'projects', href: '#/', current: true }])
    .map((w) => `<a href="${esc(w.href)}" ${w.current ? 'aria-current="page"' : ''} title="${w.attention ? 'Needs attention' : ''}"><span class="n">${w.n}:</span>${esc(w.label)}<span class="flag" aria-hidden="true">${w.current ? '*' : w.attention ? '!' : ''}</span></a>`)
    .join('');
  const clock = fmtTime(new Date());
  document.getElementById('tmux-right').innerHTML = `${right}<span>${esc(clock)}</span>`;
}

function projectWindows(p, current) {
  const attention = {
    authorization: !authActive(p) || p.problems.some((x) => /undertaking/i.test(x)),
    target: !p.target.baseUrl || !p.target.endpoints.some((e) => e.enabled) || p.problems.some((x) => /scope|verified/i.test(x)),
    accounts: !p.accounts.some((a) => a.hasSecret),
    controls: p.problems.some((x) => /window/i.test(x)),
    scans: false,
    settings: false,
  };
  return TABS.map(([key, label], n) => ({ n, label, href: `#/p/${p.id}/${key}`, current: key === current, attention: attention[key] }));
}

function projectRight(p) {
  const run = p.running.length ? '<span>scan running</span>' : '';
  const ready = p.problems.length ? `<span>${p.problems.length} blocking</span>` : '<span>ready</span>';
  return `${run}${ready}`;
}

// ---------- Accounts (public pages) ----------

function guestShell(label) {
  clearInterval(pollTimer);
  document.getElementById('tmux').hidden = true;
  for (const id of ['logout', 'nav-account', 'nav-admin']) document.getElementById(id).hidden = true;
  document.getElementById('banner').innerHTML = '';
  document.getElementById('path').innerHTML = `<span class="who">guest@breakapi</span><span class="sep">:</span><span class="here">${esc(label)}</span><span class="sep">$</span><span class="caret" aria-hidden="true"></span>`;
  app.className = '';
}

const guestPanel = (title, body) => `<section class="pane login"><div class="pane-title"><h2>${title}</h2></div><div class="pane-body">${body}</div></section>`;
const PW_HELP = '<span class="help">At least 12 characters. A few unrelated words works well.</span>';
const note = (kind, html) => `<p class="note ${kind}">${html}</p>`;

function renderLogin(message) {
  guestShell('login');
  view = { name: 'login' };
  app.innerHTML = guestPanel('Sign in', `
    ${message ? note('bad', esc(message)) : ''}
    <form id="login-form">
      <div class="field"><label for="le">Email</label><input id="le" type="email" name="email" autocomplete="username" required autofocus></div>
      <div class="field"><label for="lp">Password</label><input id="lp" type="password" name="password" autocomplete="current-password" required></div>
      <button class="btn primary" type="submit">Sign in</button>
    </form>
    <div class="guest-links"><a href="#/forgot">Forgot your password?</a>${authInfo?.signupOpen ? '<a href="#/signup">Create an account</a>' : '<span class="dim">New here? Ask an administrator for an invitation.</span>'}</div>`);
  onSubmit(document.getElementById('login-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/login', { email: v.email, password: v.password }), null, btn);
    if (!r) return;
    me = r.user;
    const next = afterLogin && !/^#\/(login|setup)/.test(afterLogin) ? afterLogin : '#/';
    afterLogin = '#/';
    if (location.hash === next) route();
    else location.hash = next;
  });
}

function renderSetup() {
  guestShell('setup');
  view = { name: 'setup' };
  app.innerHTML = guestPanel('Create the first administrator', `
    <p class="dim">No accounts exist yet. The setup token is printed in the server log when breakAPI starts and saved in the data directory as <code>setup-token</code>. It works once.</p>
    <form id="setup-form">
      <div class="field"><label for="st">Setup token</label><input id="st" type="password" name="setupToken" required autocomplete="off"></div>
      <div class="field"><label for="sn">Your name</label><input id="sn" type="text" name="name" required autocomplete="name"></div>
      <div class="field"><label for="se">Email</label><input id="se" type="email" name="email" required autocomplete="username"></div>
      <div class="field"><label for="sp">Password</label><input id="sp" type="password" name="password" required autocomplete="new-password" minlength="12">${PW_HELP}</div>
      <button class="btn primary" type="submit">Create administrator</button>
    </form>`);
  onSubmit(document.getElementById('setup-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/setup', v), 'Administrator created', btn);
    if (r) {
      me = r.user;
      location.hash = '#/';
    }
  });
}

function renderSignup() {
  guestShell('signup');
  view = { name: 'signup' };
  if (!authInfo?.signupOpen) {
    app.innerHTML = guestPanel('Sign-up is closed', '<p>This server only accepts invited users. Ask an administrator to invite you.</p><div class="guest-links"><a href="#/login">Back to sign in</a></div>');
    return;
  }
  app.innerHTML = guestPanel('Create an account', `
    <form id="signup-form">
      <div class="field"><label for="un">Name</label><input id="un" type="text" name="name" required autocomplete="name"></div>
      <div class="field"><label for="ue">Email</label><input id="ue" type="email" name="email" required autocomplete="username"><span class="help">We send a link to confirm the address. You can't run tests until it's verified.</span></div>
      <div class="field"><label for="up">Password</label><input id="up" type="password" name="password" required autocomplete="new-password" minlength="12">${PW_HELP}</div>
      <button class="btn primary" type="submit">Create account</button>
    </form>
    <div class="guest-links"><a href="#/login">Already have an account? Sign in</a></div>`);
  onSubmit(document.getElementById('signup-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/signup', v), null, btn);
    if (r) app.innerHTML = guestPanel('Check your email', `${note('ok', esc(r.message))}<div class="guest-links"><a href="#/login">Go to sign in</a></div>`);
  });
}

function renderForgot() {
  guestShell('forgot');
  view = { name: 'forgot' };
  app.innerHTML = guestPanel('Reset your password', `
    <form id="forgot-form">
      <div class="field"><label for="fe">Email</label><input id="fe" type="email" name="email" required autocomplete="username" autofocus></div>
      <button class="btn primary" type="submit">Send reset link</button>
    </form>
    <div class="guest-links"><a href="#/login">Back to sign in</a></div>`);
  onSubmit(document.getElementById('forgot-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/forgot', v), null, btn);
    if (r) app.innerHTML = guestPanel('Check your email', `${note('ok', esc(r.message))}<p class="dim small">The link works once and expires in an hour.</p><div class="guest-links"><a href="#/login">Back to sign in</a></div>`);
  });
}

function renderReset(token) {
  guestShell('reset');
  view = { name: 'reset' };
  app.innerHTML = guestPanel('Choose a new password', `
    <form id="reset-form">
      <div class="field"><label for="rp">New password</label><input id="rp" type="password" name="password" required autocomplete="new-password" minlength="12" autofocus>${PW_HELP}</div>
      <button class="btn primary" type="submit">Save password</button>
    </form>
    <p class="dim small">Saving signs you out on every device.</p>`);
  onSubmit(document.getElementById('reset-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/reset', { token, password: v.password }), null, btn);
    if (r) app.innerHTML = guestPanel('Password changed', `${note('ok', 'Your password was changed. Sign in with the new one.')}<div class="guest-links"><a href="#/login">Sign in</a></div>`);
  });
}

async function renderVerify(token) {
  guestShell('verify');
  view = { name: 'verify' };
  app.innerHTML = guestPanel('Verifying your email…', '<p class="dim">One moment.</p>');
  try {
    const r = await api('POST', '/api/auth/verify', { token });
    app.innerHTML = guestPanel('Email verified', `${note('ok', `<b>${esc(r.email)}</b> is verified. You can now create projects and run tests.`)}<div class="guest-links"><a href="#/">Continue</a></div>`);
  } catch (err) {
    app.innerHTML = guestPanel('Link not valid', `${note('bad', esc(err.message))}<div class="guest-links"><a href="#/account">Send a new link from your account page</a></div>`);
  }
}

async function renderInvite(token) {
  guestShell('invite');
  view = { name: 'invite' };
  let info;
  try {
    info = await api('GET', `/api/auth/invite/${encodeURIComponent(token)}`);
  } catch (err) {
    app.innerHTML = guestPanel('Invitation not valid', `${note('bad', esc(err.message))}<div class="guest-links"><a href="#/login">Sign in</a></div>`);
    return;
  }
  app.innerHTML = guestPanel('Join breakAPI', `
    <p>You were invited as <b>${esc(info.email)}</b>.</p>
    <form id="invite-form">
      <div class="field"><label for="in">Your name</label><input id="in" type="text" name="name" required autocomplete="name" value="${esc(info.name)}"></div>
      <div class="field"><label for="ip">Password</label><input id="ip" type="password" name="password" required autocomplete="new-password" minlength="12">${PW_HELP}</div>
      <button class="btn primary" type="submit">Create my account</button>
    </form>`);
  onSubmit(document.getElementById('invite-form'), async (v, btn) => {
    const r = await act(() => api('POST', '/api/auth/invite/accept', { token, ...v }), 'Welcome to breakAPI', btn);
    if (r) {
      me = r.user;
      location.hash = '#/';
    }
  });
}

/** The authorizer's page: reached from an emailed link, no breakAPI account needed. */
async function renderConfirm(token) {
  guestShell('confirm');
  view = { name: 'confirm' };
  let c;
  try {
    c = await api('GET', `/api/confirm/${encodeURIComponent(token)}`);
  } catch (err) {
    app.innerHTML = guestPanel('Link not valid', note('bad', esc(err.message)));
    return;
  }
  app.className = '';
  app.innerHTML = `
    <div class="page-head"><div><h1>Authorize security testing</h1><p class="lede"><b>${esc(c.recordedBy?.name || c.recordedBy?.email)}</b> &lt;${esc(c.recordedBy?.email)}&gt; recorded you, <b>${esc(c.authorizerName)}</b>, as the person who authorizes these tests. Nothing is tested until you confirm.</p></div></div>
    <section class="pane"><div class="pane-title"><h2>What you are authorizing</h2><span class="end dim small">project: ${esc(c.projectName)}</span></div>
      <div class="pane-body"><dl class="kv">
        <dt>Hosts in scope</dt><dd>${c.allowedHosts.map((h) => `<code>${esc(h)}</code>`).join(' ')}</dd>
        <dt>Tests</dt><dd>${c.allowedTests.map(esc).join('; ')}</dd>
        <dt>Write requests</dt><dd>${c.allowWriteMethods ? '<span class="c-medium">Allowed</span>, only to endpoints opted in, with synthetic data. DELETE is never sent.' : 'Not allowed (read-only)'}</dd>
        <dt>Expires</dt><dd>${fmtDate(c.expiresAt)}</dd>
        <dt>Basis</dt><dd>${c.relationship === 'delegated' ? `Delegated — ${esc(c.delegationNote)}` : 'You own the target (or act for the organization that does)'}</dd>
      </dl></div></section>
    <section class="pane"><div class="pane-title"><h2>What this does not prove</h2></div>
      <div class="pane-body small dim"><ul class="boot">${c.authLimitations.map((l) => `<li><span>[ note ]</span><span>${esc(l)}</span></li>`).join('')}</ul></div></section>
    <section class="pane"><div class="pane-title"><h2>Testing undertaking</h2><span class="end dim small">version ${esc(c.undertaking.version)}</span></div>
      <div class="pane-body">
        <ol class="clauses">${c.undertaking.clauses.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
        ${note('warn', esc(c.undertaking.notice))}
        <form id="confirm-form">
          <label class="check"><input type="checkbox" name="accepted" required> I accept this undertaking and authorize these tests.</label>
          <div class="field"><label for="ctn">Type your full name to confirm <span class="hint">${esc(c.authorizerName)}</span></label><input id="ctn" type="text" name="typedName" required autocomplete="name"></div>
          <div class="cmd"><button class="btn primary" type="submit">Confirm authorization</button><button class="btn danger" id="decline" type="button">Decline</button></div>
        </form>
      </div></section>`;
  const done = (html) => {
    app.innerHTML = guestPanel('Thank you', html);
  };
  onSubmit(document.getElementById('confirm-form'), async (v, btn) => {
    const r = await act(() => api('POST', `/api/confirm/${encodeURIComponent(token)}`, { accepted: v.accepted, typedName: v.typedName }), null, btn);
    if (r) done(note('ok', 'The authorization is confirmed. The team can now run the tests you authorized, until it expires or someone revokes it.'));
  });
  document.getElementById('decline').addEventListener('click', async (e) => {
    if (!await confirmDialog('Decline this authorization? No tests will run, and the person who recorded it will see that you declined.', 'Decline')) return;
    const r = await act(() => api('POST', `/api/confirm/${encodeURIComponent(token)}`, { decision: 'decline' }), null, e.currentTarget);
    if (r) done(note('warn', 'You declined. Nothing will be tested under this authorization.'));
  });
}

// ---------- Account & admin ----------

async function renderAccount() {
  view = { name: 'account' };
  const sessions = await api('GET', '/api/auth/sessions');
  setShell({ path: [{ label: 'account', href: '#/account' }], right: `<span>${esc(me.role)}</span>` });
  app.className = '';
  app.innerHTML = `
    <div class="page-head"><div><h1>Your account</h1><div class="sub">${esc(me.email)} · ${esc(me.role)}</div></div></div>
    <section class="pane"><div class="pane-title"><h2>Identity</h2><span class="end">${me.emailVerified ? '<span class="st st-completed">email verified</span>' : '<span class="st st-paused">email not verified</span>'}</span></div>
      <div class="pane-body">
        ${me.emailVerified ? '<p class="dim small">Your verified email is recorded on every authorization you record and every scan you start.</p>' : `<p>Verify your email to create projects and run tests.</p><p><button class="btn" id="resend" type="button">Send verification link</button></p>`}
        <form id="profile-form" class="cmd"><label class="ps" for="pn">name=</label><input id="pn" type="text" name="name" required value="${esc(me.name)}"><button class="btn" type="submit">Save name</button></form>
      </div></section>
    <section class="pane"><div class="pane-title"><h2>Change password</h2><span class="end dim small">signs out your other devices</span></div>
      <div class="pane-body"><form id="pw-form">
        <div class="grid2">
          <div class="field"><label for="pc">Current password</label><input id="pc" type="password" name="current" required autocomplete="current-password"></div>
          <div class="field"><label for="pw">New password</label><input id="pw" type="password" name="password" required autocomplete="new-password" minlength="12">${PW_HELP}</div>
        </div>
        <button class="btn primary" type="submit">Change password</button>
      </form></div></section>
    <section class="pane"><div class="pane-title"><h2>Sessions</h2><span class="end"><button class="btn danger sm" id="logout-all" type="button">Sign out everywhere</button></span></div>
      <div class="table-wrap"><table><thead><tr><th>Signed in</th><th>Last active</th><th>IP</th><th>Browser</th><th></th></tr></thead>
        <tbody>${sessions.map((x) => `<tr><td>${fmtDate(x.createdAt)}</td><td>${fmtDate(x.lastSeenAt)}</td><td>${esc(x.ip)}</td><td class="dim">${esc(x.userAgent.slice(0, 60))}</td><td>${x.current ? '<span class="st st-completed">this session</span>' : ''}</td></tr>`).join('')}</tbody></table></div></section>`;
  document.getElementById('resend')?.addEventListener('click', async (e) => {
    await act(() => api('POST', '/api/auth/resend-verification'), 'Verification link sent — check your inbox', e.currentTarget);
  });
  onSubmit(document.getElementById('profile-form'), async (v, btn) => {
    const r = await act(() => api('PATCH', '/api/auth/profile', v), 'Name saved', btn);
    if (r) me = r.user;
  });
  onSubmit(document.getElementById('pw-form'), async (v, btn) => {
    if (await act(() => api('POST', '/api/auth/password', v), 'Password changed', btn)) renderAccount();
  });
  document.getElementById('logout-all').addEventListener('click', async (e) => {
    if (!await confirmDialog('Sign out of breakAPI on every device, including this one?', 'Sign out everywhere')) return;
    if (await act(() => api('POST', '/api/auth/logout-all'), null, e.currentTarget)) {
      me = null;
      location.hash = '#/login';
    }
  });
}

async function renderAdmin() {
  view = { name: 'admin' };
  if (me.role !== 'admin') {
    app.innerHTML = note('bad', 'Administrators only.');
    return;
  }
  const [overview, users, events, orphans] = await Promise.all([api('GET', '/api/admin/overview'), api('GET', '/api/admin/users'), api('GET', '/api/admin/audit'), api('GET', '/api/admin/orphans')]);
  setShell({ path: [{ label: 'admin', href: '#/admin' }], right: `<span>${overview.counts.users} users · ${overview.counts.runningScans} running</span>` });
  const stateOf = (u) => (u.disabled ? '<span class="st st-failed">disabled</span>' : u.invited ? '<span class="st st-paused">invited</span>' : u.emailVerified ? '<span class="st st-completed">active</span>' : '<span class="st st-paused">unverified</span>');
  const c = overview.config;
  app.className = '';
  app.innerHTML = `
    <div class="page-head"><div><h1>Administration</h1><div class="sub">breakAPI ${esc(overview.version)} · ${esc(c.env)}</div></div></div>
    <section class="pane"><div class="pane-title"><h2>Server</h2><span class="dim">read-only; set through environment variables</span></div>
      <div class="pane-body"><dl class="kv">
        <dt>Public URL</dt><dd>${esc(c.publicUrl || 'not set (development)')}</dd>
        <dt>Sign-up</dt><dd>${esc(c.signup)}</dd>
        <dt>Local targets</dt><dd>${c.allowLocalTargets ? '<span class="c-medium">allowed</span>' : 'refused'}</dd>
        <dt>Private-network targets</dt><dd>${c.allowPrivateTargets ? '<span class="c-medium">allowed</span>' : 'refused'}</dd>
        <dt>Email</dt><dd>${esc(c.mail)}</dd>
        <dt>Encryption key</dt><dd>${esc(c.secretKey)}</dd>
        <dt>Sessions</dt><dd>${esc(c.sessionHours)} h idle timeout · ${overview.counts.sessions} active</dd>
        <dt>Scans</dt><dd>${overview.counts.runningScans} running of at most ${esc(c.maxConcurrentScans)} · ${overview.counts.scans} total · ${overview.counts.projects} projects</dd>
      </dl></div></section>
    <section class="pane"><div class="pane-title"><h2>Invite a user</h2></div>
      <div class="pane-body"><form id="invite-user" class="cmd">
        <label class="ps" for="iu">$ breakapi invite</label>
        <input id="iu" type="email" name="email" required placeholder="teammate@example.com">
        <select name="role" aria-label="Role" class="inline-select"><option value="user">user</option><option value="admin">admin</option></select>
        <button class="btn primary" type="submit">Send invitation</button>
      </form><span class="help">They get a one-time link (valid 72 hours) to set their name and password; their email counts as verified once they use it.</span></div></section>
    <section class="pane"><div class="pane-title"><h2>Users</h2><span class="dim">${users.length} total</span></div>
      <div class="table-wrap"><table id="users">
        <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>State</th><th>Projects</th><th>Last sign-in</th><th></th></tr></thead>
        <tbody>${users.map((u) => `<tr data-id="${esc(u.id)}">
          <td>${esc(u.email)}${u.id === me.id ? ' <span class="dim">(you)</span>' : ''}</td>
          <td>${esc(u.name || '—')}</td>
          <td><select class="inline-select" data-role aria-label="Role for ${esc(u.email)}" ${u.id === me.id ? 'disabled' : ''}><option value="user" ${u.role === 'user' ? 'selected' : ''}>user</option><option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option></select></td>
          <td>${stateOf(u)}</td>
          <td>${u.projects}</td>
          <td class="dim">${u.lastLoginAt ? fmtDate(u.lastLoginAt) : 'never'}</td>
          <td><div class="cmd">${u.invited || !u.emailVerified ? '<button class="btn sm" data-act="resend" type="button">Resend</button>' : ''}${u.id === me.id ? '' : `<button class="btn sm" data-act="${u.disabled ? 'enable' : 'disable'}" type="button">${u.disabled ? 'Enable' : 'Disable'}</button><button class="btn danger sm" data-act="delete" type="button">Delete</button>`}</div></td>
        </tr>`).join('')}</tbody></table></div></section>
    ${orphans.length ? `<section class="pane"><div class="pane-title"><h2>Projects nobody owns</h2><span class="dim">${orphans.length} · from before accounts existed</span></div>
      <div class="pane-body small dim">These can't be opened by anyone, so they can't be deleted from the project list either. Claim one to become its owner, or delete it. You see only its name, address and scan count.</div>
      <div class="table-wrap"><table id="orphans"><thead><tr><th>Name</th><th>Base URL</th><th>Scans</th><th>Created</th><th></th></tr></thead>
        <tbody>${orphans.map((o) => `<tr data-id="${esc(o.id)}" data-name="${esc(o.name)}"><td>${esc(o.name)}</td><td class="dim">${esc(o.baseUrl || '—')}</td><td>${o.scans}</td><td class="dim">${fmtDate(o.createdAt)}</td><td><div class="cmd"><button class="btn sm" data-orphan="claim" type="button">Claim</button><button class="btn danger sm" data-orphan="delete" type="button">Delete</button></div></td></tr>`).join('')}</tbody></table></div></section>` : ''}
    <section class="pane"><div class="pane-title"><h2>System audit log</h2><span class="dim">last ${events.length}</span></div>
      <div class="dmesg">${events.map((e) => `<div><span class="ts">${esc(fmtDate(e.at))}</span> <span>${esc(e.event)}</span> <span class="msg">${esc([e.email, e.by && `by ${e.by}`, e.role, e.ip].filter(Boolean).join(' · '))}</span></div>`).join('') || '<div class="msg">No events yet.</div>'}</div></section>`;
  onSubmit(document.getElementById('invite-user'), async (v, btn) => {
    if (await act(() => api('POST', '/api/admin/users', v), `Invitation sent to ${v.email}`, btn)) renderAdmin();
  });
  document.getElementById('orphans')?.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-orphan]');
    const row = btn?.closest('tr');
    if (!btn || !row) return;
    const { id, name } = row.dataset;
    if (btn.dataset.orphan === 'delete' && !await confirmDialog(`Delete "${name}" and everything in it? This cannot be undone.`, 'Delete project')) return;
    const call = btn.dataset.orphan === 'claim' ? () => api('POST', `/api/admin/orphans/${id}/claim`) : () => api('DELETE', `/api/admin/orphans/${id}`);
    if (await act(call, btn.dataset.orphan === 'claim' ? `You now own "${name}"` : 'Project deleted', btn)) renderAdmin();
  });
  const table = document.getElementById('users');
  table.addEventListener('change', async (e) => {
    const id = e.target.closest('tr')?.dataset.id;
    if (e.target.matches('[data-role]') && id && !await act(() => api('PATCH', `/api/admin/users/${id}`, { role: e.target.value }), 'Role updated')) renderAdmin();
  });
  table.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    const id = btn?.closest('tr')?.dataset.id;
    if (!btn || !id) return;
    const email = btn.closest('tr').children[0].textContent;
    const actions = {
      resend: () => api('POST', `/api/admin/users/${id}/resend`),
      disable: async () => (await confirmDialog(`Disable ${email}? They are signed out at once and any scan they started stops.`, 'Disable') ? api('PATCH', `/api/admin/users/${id}`, { disabled: true }) : null),
      enable: () => api('PATCH', `/api/admin/users/${id}`, { disabled: false }),
      delete: async () => (await confirmDialog(`Delete ${email}? This cannot be undone. Users who own projects must hand them over first.`, 'Delete user') ? api('DELETE', `/api/admin/users/${id}`) : null),
    };
    const r = await act(actions[btn.dataset.act], null, btn);
    if (r) {
      toast(btn.dataset.act === 'resend' ? 'Link sent' : 'Saved');
      renderAdmin();
    }
  });
}

// ---------- Home ----------

function countsInline(counts = {}) {
  const parts = SEVERITIES.filter((s) => counts[s]).map((s) => `<span class="c-${s}">${counts[s]} ${SEV_SHORT[s]}</span>`);
  return parts.length ? parts.join(' <span class="dim">·</span> ') : '<span class="dim">no findings</span>';
}

async function renderHome() {
  view = { name: 'home' };
  const projects = await api('GET', '/api/projects');
  setShell({ path: [{ label: 'projects', href: '#/' }], right: `<span>${projects.length} project${projects.length === 1 ? '' : 's'}</span>` });
  app.className = '';
  app.innerHTML = `
    <div class="page-head">
      <div>
        <h1>How secure is your API?</h1>
        <p class="lede">breakAPI checks APIs you own or are authorized to test for broken access control, login gaps, one user reading another's data, unsafe input handling, misconfiguration and missing rate limits. Nothing is sent until an authorization is recorded and the target is in scope.</p>
      </div>
    </div>
    <section class="pane">
      <div class="pane-title"><h2>New project</h2><span class="end dim small">press <kbd>n</kbd></span></div>
      <div class="pane-body">
        <form id="new-project" class="cmd">
          <label class="ps" for="pname">$ breakapi new</label>
          <input id="pname" type="text" name="name" placeholder="Payments API — staging" required maxlength="120">
          <button class="btn primary" type="submit">Create project</button>
        </form>
      </div>
    </section>
    <section class="pane">
      <div class="pane-title"><h2>Projects</h2><span class="dim">ls ~/projects</span></div>
      ${projects.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Base URL</th><th>Authorization</th><th>Last scan</th><th></th></tr></thead>
        <tbody>${projects.map((p) => `<tr>
          <td><a href="#/p/${esc(p.id)}">${esc(p.name)}</a></td>
          <td class="dim">${esc(p.baseUrl || '—')}</td>
          <td>${p.pendingConfirmation ? '<span class="st-paused">awaiting confirmation</span>' : p.authorizedUntil ? (new Date(p.authorizedUntil) > new Date() ? `<span class="st-completed">valid</span> <span class="dim">until ${fmtDate(p.authorizedUntil)}</span>` : '<span class="c-high">expired</span>') : '<span class="dim">none</span>'}</td>
          <td>${p.lastScan ? `${status(p.lastScan.status)} <span class="dim">·</span> ${countsInline(p.lastScan.counts)}` : '<span class="dim">never scanned</span>'}</td>
          <td><button class="btn ${p.myRole === 'owner' ? 'danger' : 'ghost'} sm" data-leave="${esc(p.id)}" data-owner="${p.myRole === 'owner'}" data-name="${esc(p.name)}" type="button" aria-label="${p.myRole === 'owner' ? 'Delete' : 'Leave'} ${esc(p.name)}">${p.myRole === 'owner' ? 'Delete' : 'Leave'}</button></td>
        </tr>`).join('')}</tbody></table></div>`
    : `<div class="pane-body"><p class="dim">No projects yet. Here is how a test goes:</p>
        <ol class="howto">
          <li><b>Create a project</b> for one API.</li>
          <li><b>Record who authorizes the test</b> and what may be tested. If that’s someone else, they confirm from an email.</li>
          <li><b>Point it at your API</b>: a base URL and an OpenAPI spec, Postman collection or list of endpoints.</li>
          <li><b>Add two test accounts</b> with their own data, so breakAPI can check whether one can reach the other’s.</li>
          <li><b>Run a scan</b>, read each finding’s fix, and retest to confirm it’s gone.</li>
        </ol></div>`}
    </section>`;
  document.querySelector('.pane table')?.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-leave]');
    if (!btn) return;
    const owner = btn.dataset.owner === 'true';
    const name = btn.dataset.name;
    const ok = await confirmDialog(owner
      ? `Delete "${name}"? This permanently removes its authorization record, credentials, scans and reports.`
      : `Leave "${name}"? You will lose access to its findings and reports.`, owner ? 'Delete project' : 'Leave project');
    if (!ok) return;
    const call = owner ? () => api('DELETE', `/api/projects/${btn.dataset.leave}`) : () => api('DELETE', `/api/projects/${btn.dataset.leave}/members/${me.id}`);
    if (await act(call, owner ? 'Project deleted' : 'You left the project', btn)) renderHome();
  });
  onSubmit(document.getElementById('new-project'), async (v, btn) => {
    const p = await act(() => api('POST', '/api/projects', { name: v.name }), null, btn);
    if (p) location.hash = `#/p/${p.id}/authorization`;
  });
}

// ---------- Project ----------

function authActive(p) {
  const a = p.authorization;
  return !!a && !a.revokedAt && !!a.confirmedAt && new Date(a.expiresAt) > new Date();
}

const problemTab = (problem) => (/authoriz|attestation|test categor|undertaking|confirm/i.test(problem) ? 'authorization' : /window/i.test(problem) ? 'controls' : 'target');

/** The one thing to do next on this project, as a link. */
function nextStep(p) {
  const link = (tab, text) => `<a href="#/p/${esc(p.id)}/${tab}">${esc(text)}</a>`;
  if (!p.authorization || p.authorization.revokedAt || (p.authorization.confirmedAt && new Date(p.authorization.expiresAt) <= new Date())) return link('authorization', 'Record who authorizes this test');
  if (!p.authorization.confirmedAt) return `Waiting for ${esc(p.authorization.authorizerEmail)} to confirm · ${link('authorization', 'resend')}`;
  if (!p.target.endpoints.length) return link('target', 'Import your endpoints');
  if (p.problems.length) return link(problemTab(p.problems[0]), p.problems[0].replace(/\.$/, ''));
  if (!p.accounts.some((a) => a.hasSecret)) return `${link('accounts', 'Add two test accounts')} <span class="dim">(optional, but most checks need them)</span> · or ${link('scans', 'start a scan')}`;
  return link('scans', 'Ready: start a scan');
}

function readiness(p) {
  const items = [];
  if (authActive(p)) items.push(['ok', `Authorization valid until ${fmtDate(p.authorization.expiresAt)}`, 'authorization']);
  if (p.target.baseUrl && p.target.endpoints.some((e) => e.enabled)) items.push(['ok', `${p.target.endpoints.filter((e) => e.enabled).length} endpoints on ${p.target.baseUrl}`, 'target']);
  const withIds = p.accounts.filter((a) => a.hasSecret && Object.keys(a.resourceIds || {}).length).length;
  if (p.accounts.some((a) => a.hasSecret)) {
    items.push(withIds >= 2 ? ['ok', `${p.accounts.filter((a) => a.hasSecret).length} test accounts`, 'accounts'] : ['warn', 'Cross-account checks need two accounts with resource IDs', 'accounts']);
  } else {
    items.push(['warn', 'No test accounts — authenticated checks will be limited', 'accounts']);
  }
  for (const problem of p.problems) {
    const where = problemTab(problem);
    items.push(['fail', problem, where]);
  }
  return `<ul class="boot">${items.map(([k, text, where]) => `<li><span class="${k}">[${k === 'ok' ? '  OK  ' : k === 'warn' ? ' WARN ' : ' FAIL '}]</span><a href="#/p/${esc(p.id)}/${where}">${esc(text)}</a></li>`).join('')}</ul>`;
}

async function renderProject(id, tab) {
  if (tab === 'team') tab = 'settings'; // old links
  meta ??= await api('GET', '/api/meta');
  const p = await api('GET', `/api/projects/${id}`);
  // With no tab in the URL, open where the work is: the first blocker, or Scans once ready.
  const current = TABS.some(([k]) => k === tab) ? tab : (p.problems.length ? problemTab(p.problems[0]) : 'scans');
  view = { name: 'project', id, tab: current, project: p };
  setShell({
    path: [{ label: 'projects', href: '#/' }, { label: slug(p.name), href: `#/p/${p.id}` }, { label: current, href: `#/p/${p.id}/${current}` }],
    windows: projectWindows(p, current),
    session: slug(p.name),
    right: projectRight(p),
  });
  app.className = '';
  app.innerHTML = `
    <div class="page-head">
      <div><h1>${esc(p.name)}</h1><div class="sub">${esc(p.target.baseUrl || 'no base URL yet')} · ${esc(p.id)}</div>
        <p class="next"><span class="dim">next:</span> ${nextStep(p)}</p></div>
    </div>
    <div id="tab"></div>`;
  const views = { authorization: authorizationTab, target: targetTab, accounts: accountsTab, controls: controlsTab, scans: scansTab, settings: teamTab };
  await views[current](document.getElementById('tab'), p, () => renderProject(id, current));
}

// What each test category actually sends, in one line (shown where tests are chosen).
const TEST_HELP = {
  config: 'A few GETs with a test Origin header, to check transport, CORS and security headers.',
  exposure: 'GETs for well-known files such as /.env and /.git/config; only content matching a signature is reported.',
  authn: 'Your endpoints called with no credential, a fake one, and altered copies of your test JWTs.',
  authz: 'One test account asking for another account’s objects; regular accounts calling admin-only endpoints.',
  input: 'A stray quote, an inert marker tag and a traversal path in parameters. GET only.',
  ratelimit: 'One short burst (your burst setting) to one endpoint, looking for HTTP 429.',
  validation: 'Fake data with malformed emails and wrong types, only to endpoints you opt in.',
  identity: 'Sign-ups and logins with fake identities, only to endpoints you opt in.',
  logic: 'Orders with negative quantities and changed prices, only to endpoints you opt in.',
};
const READ_TESTS = ['config', 'exposure', 'authn', 'authz', 'input', 'ratelimit'];
const WRITE_TESTS = ['validation', 'identity', 'logic'];
const fmtSeconds = (iso) => new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** Echo every datetime picker in the app's own date format, so the native picker's locale can't mislead. */
function wireDateEchoes(root) {
  for (const input of root.querySelectorAll('input[type="datetime-local"]')) {
    const echo = document.createElement('span');
    echo.className = 'help date-echo';
    echo.setAttribute('aria-live', 'polite');
    const update = () => { echo.textContent = input.value ? `= ${fmtDate(fromLocalInput(input.value))}` : 'not set'; };
    input.after(echo);
    input.addEventListener('input', update);
    update();
  }
}

const auditList = (events) => `<div class="dmesg">${events.map((e) => `<div><span class="ts">${esc(fmtSeconds(e.at))}</span> <span>${esc(e.event)}</span>${e.reason ? ` <span class="msg">— ${esc(e.reason)}</span>` : ''}${e.by ? ` <span class="msg">by ${esc(e.by)}</span>` : ''}${e.to ? ` <span class="msg">to ${esc(e.to)}</span>` : ''}</div>`).join('') || '<div class="msg">No events yet.</div>'}</div>`;

function authorizationTab(el, p, rerender) {
  const a = p.authorization;
  const active = authActive(p);
  const pending = !!a && !a.confirmedAt && !a.revokedAt;
  const formOpen = !a || (!active && !pending);
  const prefill = a || { authorizerName: me.name, authorizerEmail: me.email };
  const defaultHost = p.target.baseUrl ? new URL(p.target.baseUrl).host : '';
  const defaultExpiry = new Date(Date.now() + 7 * 86400000).toISOString();
  const testBox = (id) => {
    const t = meta.tests.find((x) => x.id === id);
    return `<label class="check"><input type="checkbox" name="test:${id}" ${!prefill.allowedTests || prefill.allowedTests.includes(id) ? 'checked' : ''}> <span>${esc(t.label)}<span class="help">${esc(TEST_HELP[id])}</span></span></label>`;
  };

  el.innerHTML = `
    ${a ? `<section class="pane">
      <div class="pane-title"><h2>Current authorization</h2><span class="end">${pending ? '<span class="st st-paused">awaiting confirmation</span>' : active ? '<span class="st st-completed">active</span>' : `<span class="st st-failed">${a.declinedAt ? 'declined' : a.revokedAt ? 'revoked' : 'expired'}</span>`}</span></div>
      <div class="pane-body">
        ${pending ? `<p class="note warn"><b>Waiting for ${esc(a.authorizerEmail)}.</b> We emailed them a link to review this scope and accept the undertaking. Nothing can be tested until they confirm. <button class="btn sm" id="resend-confirm" type="button">Resend the email</button></p>` : ''}
        <dl class="kv">
          <dt>Authorized by</dt><dd>${esc(a.authorizerName)} &lt;${esc(a.authorizerEmail)}&gt;${a.authorizerRole ? `, ${esc(a.authorizerRole)}` : ''}</dd>
          <dt>Why they may</dt><dd>${a.relationship === 'delegated' ? `Delegated — ${esc(a.delegationNote)}` : 'They own the target'}</dd>
          <dt>Hosts in scope</dt><dd>${a.allowedHosts.map((h) => `<code>${esc(h)}</code>`).join(' ')}</dd>
          <dt>Tests</dt><dd>${a.allowedTests.map((t) => esc(meta.tests.find((x) => x.id === t)?.label || t)).join('; ')}</dd>
          <dt>Write requests</dt><dd>${a.allowWriteMethods ? '<span class="c-medium">Allowed</span>, only to endpoints you opt in · DELETE never sent' : 'Read-only (GET, HEAD, OPTIONS)'}</dd>
          <dt>Undertaking</dt><dd>${a.undertaking ? `accepted by ${esc(a.undertaking.typedName)}, ${fmtDate(a.undertaking.acceptedAt)} <span class="dim">· version ${esc(a.undertaking.version)}${a.undertaking.acceptedVia ? ` · ${esc(a.undertaking.acceptedVia)}` : ''}</span>` : pending ? '<span class="c-medium">pending — the authorizer accepts it when confirming</span>' : '<span class="c-high">not accepted</span>'}</dd>
          <dt>Recorded</dt><dd>${fmtDate(a.recordedAt)}${a.recordedBy ? ` by ${esc(a.recordedBy.email)}` : ''}</dd>
          <dt>Confirmed</dt><dd>${a.confirmedAt ? `${fmtDate(a.confirmedAt)} <span class="dim">· ${esc(a.confirmedVia || '')}</span>` : '<span class="c-medium">not yet</span>'}</dd>
          <dt>Expires</dt><dd>${fmtDate(a.expiresAt)}</dd>
        </dl>
        <div class="cmd actions-row">
          ${active || pending ? '<button class="btn danger sm" id="revoke" type="button">Revoke</button>' : ''}
          ${formOpen ? '' : '<button class="btn sm" id="replace" type="button" aria-expanded="false" aria-controls="auth-section">Replace authorization</button>'}
          ${active ? '<span class="dim small">Revoking stops running scans and deletes stored credentials.</span>' : ''}
        </div>
      </div>
    </section>` : '<p class="note warn"><b>No authorization yet.</b> Nothing is sent to any API until the person who may authorize testing confirms it, here or from an emailed link.</p>'}

    <section class="pane" id="auth-section" ${formOpen ? '' : 'hidden'}>
      <div class="pane-title"><h2>${a ? 'Replace authorization' : 'Record authorization'}</h2><span class="end dim small">${a ? 'the current record moves to history' : 'three steps'}</span></div>
      <div class="pane-body">
      <form id="auth-form">
        <fieldset class="step">
          <legend>1 · Who authorizes this test</legend>
          <div class="grid2">
            <div class="field"><label for="an">Authorizer’s name</label><input id="an" type="text" name="authorizerName" required autocomplete="name" value="${esc(prefill.authorizerName)}"></div>
            <div class="field"><label for="ae">Authorizer’s email</label><input id="ae" type="email" name="authorizerEmail" required value="${esc(prefill.authorizerEmail)}"><span class="help">Yours by default. Anyone else gets an email to confirm it themselves.</span></div>
            <div class="field"><label for="ar">Their role <span class="hint">optional, e.g. CTO, API owner</span></label><input id="ar" type="text" name="authorizerRole" value="${esc(prefill.authorizerRole)}"></div>
          </div>
          <div class="field"><span class="label-like">Why they may authorize it</span>
            <label class="check"><input type="radio" name="relationship" value="owner" ${prefill.relationship !== 'delegated' ? 'checked' : ''}> They own this API, or act for the organization that owns it</label>
            <label class="check"><input type="radio" name="relationship" value="delegated" ${prefill.relationship === 'delegated' ? 'checked' : ''}> The owner delegated the authority to them</label>
          </div>
          <div class="field" id="delegation" ${prefill.relationship === 'delegated' ? '' : 'hidden'}>
            <label for="dn">Delegation details <span class="hint">who granted it, when, and where it is documented</span></label>
            <textarea id="dn" name="delegationNote" rows="3">${esc(prefill.delegationNote)}</textarea>
          </div>
        </fieldset>

        <fieldset class="step">
          <legend>2 · What may be tested, and until when</legend>
          <div class="grid2">
            <div class="field">
              <label for="hosts">Hosts in scope <span class="hint">one per line · host or host:port</span></label>
              <textarea id="hosts" name="allowedHosts" rows="3" required placeholder="api.example.com&#10;localhost:4010">${esc((prefill.allowedHosts || (defaultHost ? [defaultHost] : [])).join('\n'))}</textarea>
              <span class="help">No http://, paths or wildcards. Requests to any other host are refused; hosts that aren’t on this machine must also pass a DNS or file check.</span>
            </div>
            <div class="field"><label for="ax">Expires <span class="hint">at most ${meta.maxAuthorizationDays} days</span></label><input id="ax" type="datetime-local" name="expiresAt" required value="${toLocalInput(active || pending ? prefill.expiresAt : defaultExpiry)}"></div>
          </div>
          <div class="test-groups">
            <div><span class="label-like">Read-only checks</span>${READ_TESTS.map(testBox).join('')}</div>
            <div><span class="label-like">Checks that send fake data</span>${WRITE_TESTS.map(testBox).join('')}
              <label class="check write-switch"><input type="checkbox" name="allowWriteMethods" ${prefill.allowWriteMethods ? 'checked' : ''}> <span><b>Allow write requests</b> (POST/PUT/PATCH) for these. Still only to endpoints you tick on the Target tab. <span class="warnline">This creates or changes data.</span> DELETE is never sent.</span></label>
            </div>
          </div>
        </fieldset>

        <fieldset class="step" id="undertaking-block">
          <legend>3 · Accept the undertaking</legend>
          <div class="limits"><span class="label-like">What this does not prove</span><ul class="boot small dim">${meta.authLimitations.map((l) => `<li><span>[ note ]</span><span>${esc(l)}</span></li>`).join('')}</ul></div>
          <ol class="clauses">${meta.undertaking.clauses.map((c) => `<li>${esc(c)}</li>`).join('')}</ol>
          <p class="note warn">${esc(meta.undertaking.notice)}</p>
          <label class="check"><input type="checkbox" name="undertaking" required> <span>I accept this undertaking (version ${esc(meta.undertaking.version)}) and am responsible for this testing.</span></label>
          <div class="field"><label for="tn">Type <b id="type-this">${esc(prefill.authorizerName || 'your full name')}</b> to accept</label><input id="tn" type="text" name="typedName" required autocomplete="off"></div>
        </fieldset>

        <fieldset class="step" id="delegate-block" hidden>
          <legend>3 · Send it to the authorizer</legend>
          <p>When you record this, we email <b id="delegate-email"></b> a one-time link. They see this exact scope and what it does not prove, and accept the undertaking themselves, or decline. Tests stay blocked until they confirm.</p>
          <label class="check"><input type="checkbox" name="recorderConfirm"> <span>The scope above is accurate, and I’m recording it at the authorizer’s request.</span></label>
        </fieldset>

        <div class="cmd"><button class="btn primary" type="submit">Record authorization</button>${formOpen ? '' : '<button class="btn ghost" id="cancel-replace" type="button">Cancel</button>'}</div>
      </form>
      </div>
    </section>

    ${p.authorizationHistory.length ? `<details class="pane fold"><summary class="pane-title"><h2>Authorization history</h2><span class="dim">${p.authorizationHistory.length} earlier</span></summary><div class="table-wrap"><table>
      <thead><tr><th>Recorded</th><th>Authorizer</th><th>Hosts</th><th>Expires</th><th>Ended</th></tr></thead>
      <tbody>${[...p.authorizationHistory].reverse().map((h) => `<tr><td>${fmtDate(h.recordedAt)}</td><td>${esc(h.authorizerEmail)}</td><td>${esc(h.allowedHosts.join(', '))}</td><td>${fmtDate(h.expiresAt)}</td><td>${fmtDate(h.revokedAt || h.supersededAt)}</td></tr>`).join('')}</tbody>
    </table></div></details>` : ''}

    <details class="pane fold"><summary class="pane-title"><h2>Audit log</h2><span class="dim">${p.audit.length} events · journalctl -u breakapi</span></summary>
      ${auditList([...p.audit].reverse().slice(0, 100))}
    </details>`;

  wireDateEchoes(el);
  const section = document.getElementById('auth-section');
  const form = document.getElementById('auth-form');
  const replace = document.getElementById('replace');
  replace?.addEventListener('click', () => {
    section.hidden = false;
    replace.setAttribute('aria-expanded', 'true');
    form.authorizerName.focus();
  });
  document.getElementById('cancel-replace')?.addEventListener('click', () => {
    section.hidden = true;
    replace?.setAttribute('aria-expanded', 'false');
  });
  // The authorizer accepts the undertaking themselves: here if it's you, from an emailed link if not.
  const sync = () => {
    const email = form.authorizerEmail.value.trim().toLowerCase();
    const other = !!email && email !== me.email;
    document.getElementById('undertaking-block').hidden = other;
    document.getElementById('delegate-block').hidden = !other;
    document.getElementById('delegate-email').textContent = email;
    document.getElementById('type-this').textContent = form.authorizerName.value.trim() || 'the authorizer’s full name';
    form.undertaking.required = !other;
    form.typedName.required = !other;
    form.recorderConfirm.required = other;
    form.querySelector('button[type="submit"]').textContent = other ? 'Record and email the authorizer' : 'Record authorization';
  };
  sync();
  form.authorizerEmail.addEventListener('input', sync);
  form.authorizerName.addEventListener('input', sync);
  form.addEventListener('change', () => {
    document.getElementById('delegation').hidden = formValues(form).relationship !== 'delegated';
  });
  document.getElementById('resend-confirm')?.addEventListener('click', async (e) => {
    if (await act(() => api('POST', `/api/projects/${p.id}/authorization/resend`), `Sent again to ${a.authorizerEmail}`, e.currentTarget)) rerender();
  });
  onSubmit(form, async (v, btn) => {
    const other = v.authorizerEmail.trim().toLowerCase() !== me.email;
    // The undertaking (or, for someone else, the recorder's confirmation) covers the three attestations.
    const attested = other ? v.recorderConfirm : v.undertaking;
    const body = {
      authorizerName: v.authorizerName,
      authorizerEmail: v.authorizerEmail,
      authorizerRole: v.authorizerRole,
      relationship: v.relationship,
      delegationNote: v.delegationNote,
      allowedHosts: lines(v.allowedHosts),
      allowedTests: meta.tests.filter((t) => v[`test:${t.id}`]).map((t) => t.id),
      allowWriteMethods: v.allowWriteMethods,
      expiresAt: fromLocalInput(v.expiresAt),
      attestations: { ownsOrAuthorized: attested, scopeAccurate: attested, acceptsImpact: attested },
      undertaking: { accepted: v.undertaking, typedName: v.typedName },
    };
    const r = await act(() => api('PUT', `/api/projects/${p.id}/authorization`, body), null, btn);
    if (r) {
      toast(r.authorization.confirmedAt ? 'Authorization recorded' : `Recorded. We emailed ${r.authorization.authorizerEmail} to confirm.`);
      rerender();
    }
  });
  document.getElementById('revoke')?.addEventListener('click', async (e) => {
    if (!await confirmDialog('Revoke this authorization? Running scans stop immediately and stored test credentials are deleted.', 'Revoke')) return;
    if (await act(() => api('POST', `/api/projects/${p.id}/authorization/revoke`), 'Authorization revoked', e.currentTarget)) rerender();
  });
}

function targetTab(el, p, rerender) {
  const eps = p.target.endpoints;
  const queryNames = (e) => e.params.filter((x) => x.in === 'query').map((x) => x.name);
  const allLocal = p.hostStatus.length && p.hostStatus.every((h) => h.local);
  const importForm = `<form id="import-form">
        <div class="grid2">
          <div class="field"><label for="fmt">Format</label>
            <select id="fmt" name="format">
              <option value="openapi">OpenAPI 3 / Swagger 2 (JSON)</option>
              <option value="postman">Postman collection v2 (JSON)</option>
              <option value="manual">Manual list</option>
            </select></div>
          <div class="field"><label for="file">Load from file</label><input id="file" type="file" accept=".json,.txt"></div>
        </div>
        <div class="field"><label for="content">Content <span class="hint">paste a spec, a collection, or one endpoint per line</span></label>
          <textarea id="content" name="content" rows="8"></textarea>
          <span class="help">Manual format: <code>GET /users/{id}</code>, <code>GET /admin/stats admin</code>, <code>GET /health public</code></span></div>
        <label class="check"><input type="checkbox" name="replace"> Replace the existing endpoints</label>
        <button class="btn primary" type="submit">Import</button>
      </form>`;

  el.innerHTML = `
    <section class="pane">
      <div class="pane-title"><h2>Base URL</h2></div>
      <div class="pane-body">
        <form id="target-form" class="cmd">
          <label class="ps" for="burl">base_url=</label>
          <input id="burl" type="url" name="baseUrl" placeholder="https://api.example.com/v1" required value="${esc(p.target.baseUrl)}">
          <button class="btn primary" type="submit">Save</button>
        </form>
        <span class="help">Endpoint paths are added to this URL. Its host must be listed in the authorization.</span>
      </div>
    </section>

    ${!p.authorization ? '<p class="note warn"><b>No authorization yet.</b> Hosts are verified per authorization. Record one first.</p>'
    : allLocal ? '<p class="note">Every host in scope is on this machine (local development only), so there’s nothing to verify. Reports say no ownership proof was made.</p>'
    : `<section class="pane">
      <div class="pane-title"><h2>Verify control of each host</h2><span class="end dim small">checked again at the start of every scan</span></div>
      <div class="pane-body">
        <p>Publish this token for every host that isn’t local, by either method. It belongs to the current authorization; a check lasts 24 hours.</p>
        <pre>${esc(p.authorization.verificationToken)}</pre>
        <ul class="boot">
          <li><span class="dim">[ file ]</span><span><code>http(s)://&lt;host&gt;/.well-known/breakapi-verification.txt</code>, with the token on its own line</span></li>
          <li><span class="dim">[ dns  ]</span><span>a TXT record on <code>_breakapi.&lt;hostname&gt;</code> whose value is the token (names only, not IP addresses)</span></li>
        </ul>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>Status</th><th>Method</th><th></th></tr></thead>
        <tbody>${p.hostStatus.map((h) => `<tr>
          <td>${esc(h.host)}</td>
          <td>${h.refused ? '<span class="st st-failed">refused here</span>' : h.local ? '<span class="st st-paused">local only</span>' : h.verified ? '<span class="st st-completed">verified</span>' : `<span class="st st-failed">${h.stale ? 'expired' : 'not verified'}</span>`}</td>
          <td class="dim">${esc(h.refused || h.method || '—')}${h.at && !h.local ? ` · ${fmtDate(h.at)}` : ''}</td>
          <td>${h.local || h.refused ? '' : `<button class="btn sm" data-verify="${esc(h.host)}" type="button">Check</button>`}</td>
        </tr>`).join('')}</tbody></table></div>
      <div class="pane-body small dim">A passed check shows control of a token location at one moment; it is not proof of ownership.</div>
    </section>`}

    ${eps.length ? '' : `<section class="pane"><div class="pane-title"><h2>Import endpoints</h2><span class="end dim small">start here</span></div><div class="pane-body">${importForm}</div></section>`}

    <section class="pane">
      <div class="pane-title"><h2>Endpoints</h2><span class="dim">${eps.filter((e) => e.enabled && e.method !== 'DELETE').length} of ${eps.filter((e) => e.method !== 'DELETE').length} tested</span>
        ${eps.length ? '<span class="end"><button class="btn sm" id="test-all" type="button">Test all</button><button class="btn sm" id="test-none" type="button">Test none</button><button class="btn danger sm" id="clear-eps" type="button">Remove all</button></span>' : ''}</div>
      ${eps.length ? `<div class="pane-body small dim">“Needs login” and “Admin only” say what <em>should</em> happen; breakAPI reports when the API behaves otherwise. DELETE endpoints are listed but never called.<br><b>Fake-data writes:</b> tick only endpoints that are safe to send fake data to (a sign-up, an order on a test catalog). Nothing is ever sent with POST, PUT or PATCH to an endpoint you haven’t ticked, imports never tick it, and it needs “allow write requests” on the Authorization tab.</div>
      <div class="table-wrap"><table id="eps">
        <thead><tr><th>Test</th><th>Method</th><th>Path</th><th>Needs login</th><th>Admin only</th><th>Fake-data writes</th><th>Summary</th></tr></thead>
        <tbody>${eps.map((e) => `<tr data-id="${esc(e.id)}">
          <td>${e.method === 'DELETE' ? '<span class="dim" title="DELETE is never sent">never</span>' : `<input type="checkbox" data-field="enabled" aria-label="Test ${esc(e.method)} ${esc(e.path)}" ${e.enabled ? 'checked' : ''}>`}</td>
          <td class="method">${esc(e.method)}</td>
          <td>${esc(e.path)}${queryNames(e).length ? `<span class="dim">?${esc(queryNames(e).join('&'))}</span>` : ''}</td>
          <td><input type="checkbox" data-field="requiresAuth" aria-label="Needs login: ${esc(e.method)} ${esc(e.path)}" ${e.requiresAuth ? 'checked' : ''}></td>
          <td><input type="checkbox" data-field="adminOnly" aria-label="Admin only: ${esc(e.method)} ${esc(e.path)}" ${e.adminOnly ? 'checked' : ''}></td>
          <td>${['POST', 'PUT', 'PATCH'].includes(e.method) ? `<input type="checkbox" data-field="syntheticWrites" aria-label="Allow fake-data writes to ${esc(e.method)} ${esc(e.path)}" ${e.syntheticWrites ? 'checked' : ''} ${p.authorization?.allowWriteMethods ? '' : 'disabled'}> <span class="dim">${esc(e.kind)}</span>` : '<span class="dim">—</span>'}</td>
          <td class="dim">${esc(e.summary)}</td>
        </tr>`).join('')}</tbody></table></div>` : '<p class="empty">No endpoints yet. Import a spec, a Postman collection or a manual list above.</p>'}
    </section>

    ${eps.length ? `<details class="pane fold"><summary class="pane-title"><h2>Import more endpoints</h2><span class="dim">OpenAPI, Postman or a manual list</span></summary><div class="pane-body">${importForm}</div></details>` : ''}`;

  onSubmit(document.getElementById('target-form'), async (v, btn) => {
    if (await act(() => api('PUT', `/api/projects/${p.id}/target`, { baseUrl: v.baseUrl }), 'Base URL saved', btn)) rerender();
  });
  el.addEventListener('click', async (e) => {
    const host = e.target.closest('[data-verify]')?.dataset.verify;
    if (host && await act(() => api('POST', `/api/projects/${p.id}/verify`, { host }), `${host} verified`, e.target.closest('button'))) rerender();
  });
  document.getElementById('file').addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    document.getElementById('content').value = await f.text();
    if (/postman/i.test(f.name)) document.getElementById('fmt').value = 'postman';
    else if (/\.txt$/i.test(f.name)) document.getElementById('fmt').value = 'manual';
  });
  onSubmit(document.getElementById('import-form'), async (v, btn) => {
    const r = await act(() => api('POST', `/api/projects/${p.id}/import`, v), null, btn);
    if (r) {
      toast(`Imported ${r.imported} endpoints`);
      rerender();
    }
  });
  document.getElementById('clear-eps')?.addEventListener('click', async (e) => {
    if (await confirmDialog('Remove all endpoints from this project?', 'Remove all') && await act(() => api('DELETE', `/api/projects/${p.id}/endpoints`), null, e.currentTarget)) rerender();
  });
  const bulk = async (enabled, btn) => {
    const targets = eps.filter((x) => x.method !== 'DELETE' && x.enabled !== enabled);
    if (await act(async () => {
      for (const x of targets) await api('PATCH', `/api/projects/${p.id}/endpoints/${x.id}`, { enabled });
      return true;
    }, `${targets.length} endpoint${targets.length === 1 ? '' : 's'} updated`, btn)) rerender();
  };
  document.getElementById('test-all')?.addEventListener('click', (e) => bulk(true, e.currentTarget));
  document.getElementById('test-none')?.addEventListener('click', (e) => bulk(false, e.currentTarget));
  document.getElementById('eps')?.addEventListener('change', async (e) => {
    const field = e.target.dataset.field;
    const id = e.target.closest('tr')?.dataset.id;
    if (field && id) await act(() => api('PATCH', `/api/projects/${p.id}/endpoints/${id}`, { [field]: e.target.checked }), 'Saved');
  });
}

function accountsTab(el, p, rerender) {
  const paramNames = [...new Set(p.target.endpoints.flatMap((e) => e.params.filter((x) => x.in === 'path').map((x) => x.name)))];
  el.innerHTML = `
    <p class="note"><b>Test accounts only.</b> Never use real customer accounts. Credentials are encrypted at rest, masked in logs and reports, and deleted automatically when the authorization expires or is revoked.</p>
    <section class="pane">
      <div class="pane-title"><h2>Accounts</h2>${p.accounts.some((a) => a.hasSecret) ? '<span class="end"><button class="btn danger sm" id="purge" type="button">Delete all credentials</button></span>' : ''}</div>
      ${p.accounts.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Label</th><th>Role</th><th>Auth</th><th>Credential</th><th>Owns</th><th></th></tr></thead>
        <tbody>${p.accounts.map((a) => `<tr>
          <td>${esc(a.label)}</td><td>${esc(a.role)}</td>
          <td class="dim">${esc(a.authType === 'header' ? a.headerName : a.authType)}</td>
          <td>${a.hasSecret ? `<span class="dim">${esc(a.secretHint)}</span>` : '<span class="c-high">deleted</span>'}</td>
          <td>${Object.entries(a.resourceIds || {}).map(([k, v]) => `<code>${esc(k)}=${esc(v)}</code>`).join(' ') || '<span class="dim">—</span>'}</td>
          <td><button class="btn danger sm" data-del="${esc(a.id)}" type="button">Remove</button></td>
        </tr>`).join('')}</tbody></table></div>` : '<p class="empty">No accounts yet. Add two regular users with their own data to test whether one can reach the other’s.</p>'}
    </section>
    <section class="pane">
      <div class="pane-title"><h2>Add a test account</h2></div>
      <div class="pane-body">
      <form id="acct-form">
        <div class="grid2">
          <div class="field"><label for="al">Label</label><input id="al" type="text" name="label" required placeholder="alice"></div>
          <div class="field"><label for="ro">Role</label><select id="ro" name="role"><option value="user">Regular user</option><option value="admin">Admin</option></select></div>
          <div class="field"><label for="at">Authentication</label><select id="at" name="authType">
            <option value="bearer">Bearer token (Authorization header)</option>
            <option value="header">API key in a custom header</option>
            <option value="cookie">Cookie header</option></select></div>
          <div class="field" id="hn-field" hidden><label for="hn">Header name</label><input id="hn" type="text" name="headerName" placeholder="X-API-Key"></div>
          <div class="field"><label for="sec">Credential</label><input id="sec" type="password" name="secret" required autocomplete="off" placeholder="token, key or cookie string"></div>
        </div>
        <div class="field"><label for="rid">IDs of things this account owns <span class="hint">one per line, like <code>id=1</code></span></label>
          <textarea id="rid" name="resourceIds" rows="3" placeholder="id=1"></textarea>
          <span class="help">${paramNames.length ? `Path parameters in your endpoints: ${paramNames.map((n) => `<code>${esc(n)}</code>`).join(' ')}. ` : ''}The name before = must match a path parameter, so <code>id=1</code> fills <code>/users/{id}</code>. breakAPI asks for one account’s objects while signed in as another, so give each account its own IDs. Add <code>email=…</code> to let the login check use a real address.</span></div>
        <button class="btn primary" type="submit">Add account</button>
      </form>
      </div>
    </section>`;

  const form = document.getElementById('acct-form');
  form.authType.addEventListener('change', () => {
    document.getElementById('hn-field').hidden = form.authType.value !== 'header';
  });
  onSubmit(form, async (v, btn) => {
    const resourceIds = Object.fromEntries(lines(v.resourceIds).map((l) => l.split('=').map((s) => s.trim())).filter(([k, val]) => k && val));
    if (await act(() => api('POST', `/api/projects/${p.id}/accounts`, { ...v, resourceIds }), 'Account added', btn)) rerender();
  });
  el.addEventListener('click', async (e) => {
    const id = e.target.closest('[data-del]')?.dataset.del;
    if (id && await confirmDialog('Remove this test account and its stored credential?', 'Remove') && await act(() => api('DELETE', `/api/projects/${p.id}/accounts/${id}`))) rerender();
  });
  document.getElementById('purge')?.addEventListener('click', async (e) => {
    if (await confirmDialog('Delete every stored credential for this project?', 'Delete credentials') && await act(() => api('DELETE', `/api/projects/${p.id}/credentials`), 'Credentials deleted', e.currentTarget)) rerender();
  });
}

function controlsTab(el, p, rerender) {
  const c = p.controls;
  const d = meta.defaults;
  const h = meta.hardLimits;
  const num = (name, label, hint, min, max, step = 1) => `<div class="field"><label for="c-${name}">${label} <span class="hint">${hint}</span></label><input id="c-${name}" type="number" step="${step}" min="${min}" max="${max}" required name="${name}" value="${esc(c[name] ?? d[name])}"><span class="help">default ${esc(d[name])} · ${min}–${max}</span></div>`;
  el.innerHTML = `
    <section class="pane">
      <div class="pane-title"><h2>Safety controls</h2><span class="end dim small">enforced on every request · saved with each report</span></div>
      <div class="pane-body">
      <p class="dim">The defaults are deliberately conservative; most projects never change them. Server-wide ceilings apply whatever you set here.</p>
      <form id="controls-form">
        <fieldset class="step">
          <legend>How much traffic</legend>
          <div class="grid3">
            ${num('maxRequests', 'Request budget', 'per scan', 10, h.maxRequests)}
            ${num('rps', 'Speed', 'requests per second', 0.5, h.rps, 0.5)}
            ${num('maxWrites', 'Write budget', 'POST/PUT/PATCH per scan', 0, h.maxWrites)}
          </div>
        </fieldset>
        <fieldset class="step">
          <legend>The rate-limit check</legend>
          <div class="grid3">
            ${num('rateLimitBurst', 'Burst size', 'requests in that one check', 5, 500)}
            ${num('burstRps', 'Burst speed', 'requests per second during it', 1, h.burstRps)}
          </div>
        </fieldset>
        <fieldset class="step">
          <legend>When to stop</legend>
          <div class="grid3">
            ${num('stopOnErrorStreak', 'Stop after', 'server errors or timeouts in a row', 1, 100)}
            ${num('timeoutMs', 'Timeout', 'milliseconds per request', 1000, 60000, 500)}
            <div class="field"><label for="c-dur">Max duration <span class="hint">minutes</span></label><input id="c-dur" type="number" step="1" min="1" max="${Math.round(h.maxDurationMs / 60000)}" required name="maxDurationMin" value="${Math.round((c.maxDurationMs ?? d.maxDurationMs) / 60000)}"><span class="help">default ${Math.round(d.maxDurationMs / 60000)} · 1–${Math.round(h.maxDurationMs / 60000)}</span></div>
          </div>
        </fieldset>
        <fieldset class="step">
          <legend>When it may run <span class="hint">optional</span></legend>
          <div class="grid3">
            <div class="field"><label for="ws">Window opens</label><input id="ws" type="datetime-local" name="windowStart" value="${toLocalInput(c.windowStart)}"></div>
            <div class="field"><label for="we">Window closes</label><input id="we" type="datetime-local" name="windowEnd" value="${toLocalInput(c.windowEnd)}"></div>
          </div>
        </fieldset>
        <fieldset class="step">
          <legend>What to leave alone, and who is watching</legend>
          <div class="grid2">
            <div class="field"><label for="ex">Exclusions <span class="hint">paths never requested · one per line · * wildcard</span></label>
              <textarea id="ex" name="exclusions" rows="4" placeholder="/api/billing/*&#10;/api/users/*/export">${esc(c.exclusions.join('\n'))}</textarea></div>
            <div class="field"><label for="mc">Monitoring contact <span class="hint">who watches the target during the test</span></label>
              <input id="mc" type="text" name="monitoringContact" value="${esc(c.monitoringContact)}" placeholder="oncall@example.com, #ops-alerts"></div>
          </div>
        </fieldset>
        <button class="btn primary" type="submit">Save controls</button>
      </form>
      </div>
    </section>`;
  wireDateEchoes(el);
  onSubmit(document.getElementById('controls-form'), async (v, btn) => {
    const body = { ...v, maxDurationMs: Number(v.maxDurationMin) * 60000, exclusions: lines(v.exclusions), windowStart: fromLocalInput(v.windowStart), windowEnd: fromLocalInput(v.windowEnd) };
    if (await act(() => api('PUT', `/api/projects/${p.id}/controls`, body), 'Controls saved', btn)) rerender();
  });
}

async function scansTab(el, p, rerender) {
  const scans = await api('GET', `/api/projects/${p.id}/scans`);
  const busy = p.running.length > 0;
  el.innerHTML = `
    <section class="pane">
      <div class="pane-title"><h2>Pre-flight</h2><span class="dim">systemctl status breakapi-scan</span></div>
      <div class="pane-body">
        ${readiness(p)}
        ${p.problems.length ? '' : `<p class="small dim">At most <b>${p.controls.maxRequests}</b> requests at <b>${p.controls.rps}/s</b> to <code>${esc(p.target.baseUrl)}</code>. Each carries an <code>X-BreakAPI-Scan</code> header so your monitoring can spot it.</p>`}
        <button class="btn primary" id="start" type="button" ${p.problems.length || busy ? 'disabled' : ''}>${busy ? 'Scan running…' : 'Start scan'} <kbd>s</kbd></button>
      </div>
    </section>
    <section class="pane">
      <div class="pane-title"><h2>Scans</h2><span class="dim">${scans.length} total</span></div>
      ${scans.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Started</th><th>Status</th><th>Requests</th><th>Findings</th><th></th></tr></thead>
        <tbody>${scans.map((s) => `<tr>
          <td>${fmtDate(s.startedAt || s.createdAt)}${s.previousScanId ? ' <span class="dim">retest</span>' : ''}</td>
          <td>${status(s.status)}</td>
          <td>${s.requestsSent}</td>
          <td>${countsInline(s.counts)}</td>
          <td><a href="#/s/${esc(s.id)}">Open</a></td>
        </tr>`).join('')}</tbody></table></div>` : '<p class="empty">No scans yet.</p>'}
    </section>
    <section class="pane"><div class="pane-title"><h2>Limitations</h2></div><div class="pane-body small dim"><ul class="boot">${meta.limitations.map((l) => `<li><span>[ note ]</span><span>${esc(l)}</span></li>`).join('')}</ul></div></section>`;
  document.getElementById('start').addEventListener('click', async (e) => {
    const s = await act(() => api('POST', `/api/projects/${p.id}/scans`, {}), null, e.currentTarget);
    if (s) location.hash = `#/s/${s.id}`;
  });
  if (busy) {
    clearInterval(pollTimer);
    pollTimer = setInterval(() => { if (document.getElementById('start')) rerender(); }, 3000);
  }
}

function teamTab(el, p, rerender) {
  const owner = p.myRole === 'owner';
  el.innerHTML = `
    <section class="pane">
      <div class="pane-title"><h2>Members</h2><span class="dim">only members can see this project, its findings and reports</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Email</th><th>Name</th><th>Role</th><th></th></tr></thead>
        <tbody>${p.members.map((m) => `<tr>
          <td>${esc(m.email || 'deleted user')}${m.userId === me.id ? ' <span class="dim">(you)</span>' : ''}</td>
          <td>${esc(m.name || '—')}</td>
          <td>${esc(m.role)}</td>
          <td>${m.role === 'owner' ? '' : owner || m.userId === me.id ? `<button class="btn danger sm" data-remove="${esc(m.userId)}" type="button">${m.userId === me.id ? 'Leave' : 'Remove'}</button>` : ''}</td>
        </tr>`).join('')}</tbody></table></div>
    </section>
    ${owner ? `<section class="pane"><div class="pane-title"><h2>Add a member</h2></div>
      <div class="pane-body">
        <form id="member-form" class="cmd"><label class="ps" for="mem">email=</label><input id="mem" type="email" name="email" required placeholder="teammate@example.com"><button class="btn primary" type="submit">Add member</button></form>
        <span class="help">They must already have a breakAPI account. Members can configure the project and run scans; only the owner can delete it or manage members.</span>
      </div></section>
    <section class="pane danger-zone"><div class="pane-title"><h2>Delete this project</h2></div>
      <div class="pane-body"><p class="dim small">Permanently removes the authorization record, stored credentials, every scan and every report. This cannot be undone.</p>
      <button class="btn danger sm" id="delete-project" type="button">Delete project</button></div></section>` : '<p class="note">Only the owner can add members or delete this project.</p>'}`;
  document.getElementById('delete-project')?.addEventListener('click', async (e) => {
    if (!await confirmDialog(`Delete "${p.name}"? This permanently removes its authorization record, credentials, scans and reports.`, 'Delete project')) return;
    if (await act(() => api('DELETE', `/api/projects/${p.id}`), 'Project deleted', e.currentTarget)) location.hash = '#/';
  });
  document.getElementById('member-form') && onSubmit(document.getElementById('member-form'), async (v, btn) => {
    if (await act(() => api('POST', `/api/projects/${p.id}/members`, v), `${v.email} added`, btn)) rerender();
  });
  el.addEventListener('click', async (e) => {
    const id = e.target.closest('[data-remove]')?.dataset.remove;
    if (!id) return;
    const self = id === me.id;
    if (!await confirmDialog(self ? 'Leave this project? You will lose access to its findings and reports.' : 'Remove this member from the project?', self ? 'Leave' : 'Remove')) return;
    if (await act(() => api('DELETE', `/api/projects/${p.id}/members/${id}`), null, e.target.closest('button'))) {
      if (self) location.hash = '#/';
      else rerender();
    }
  });
}

// ---------- Scan ----------

function evidenceBlock(ev) {
  const reqH = Object.entries(ev.requestHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  const resH = Object.entries(ev.responseHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  return `<div class="ev">${ev.note ? `<div class="evnote">${esc(ev.note)}</div>` : ''}${ev.request ? `<pre><span class="req">${esc(ev.request)}</span>\n${esc(reqH)}${ev.requestBody ? `\n\n${esc(ev.requestBody)}` : ''}\n\n<span class="status">HTTP ${esc(ev.status)}</span>\n${esc(resH)}\n\n${esc(ev.body || '')}</pre>` : ''}</div>`;
}

function manPage(s, f) {
  if (!f) return `<div class="man"><p class="empty">${ACTIVE.includes(s.status) ? 'No findings yet. They appear here as checks complete.' : 'No findings recorded. That is not proof the API is secure — see Limitations in the report.'}</p></div>`;
  const page = `BREAKAPI-${f.check.toUpperCase()}(7)`;
  return `<article class="man" aria-labelledby="man-title">
    <div class="man-head"><span>${esc(page)}</span><span>breakAPI findings</span><span>${esc(page)}</span></div>
    <h2 class="title" id="man-title">${esc(f.title)}</h2>
    <section><h3>NAME</h3><div>${tag(f.severity)} ${esc(f.title)}</div></section>
    <section><h3>SYNOPSIS</h3><div class="syn"><b>${esc(f.endpoint)}</b>${f.param ? ` · parameter <b>${esc(f.param)}</b>` : ''} · confidence <b>${esc(f.confidence)}</b> · check <b>${esc(f.check)}</b></div></section>
    <section><h3>DESCRIPTION</h3><div><p>${esc(f.description)}</p></div></section>
    <section><h3>IMPACT</h3><div><p>${esc(f.impact)}</p></div></section>
    <section><h3>FIX</h3><div><p>${esc(f.remediation)}</p></div></section>
    ${(f.evidence || []).length ? `<section><h3>EVIDENCE</h3><div>${f.evidence.map(evidenceBlock).join('')}</div></section>` : ''}
    <div class="man-foot"><span>${esc(s.id)}</span><span>${esc(fmtDate(f.at))}</span></div>
  </article>`;
}

function dmesgLine(l, t0) {
  const secs = Math.max(0, (new Date(l.at) - t0) / 1000);
  const ts = `[${secs.toFixed(3).padStart(9, ' ')}]`;
  if (l.note) return `<div><span class="ts">${esc(ts)}</span> <span class="msg">breakapi: ${esc(l.note)}</span></div>`;
  const cls = !l.status || l.status >= 500 ? 's5' : l.status >= 400 ? 's4' : 's2';
  return `<div><span class="ts">${esc(ts)}</span> <span class="${cls}">${l.status || 'ERR'}</span> ${esc(l.method)} ${esc(l.url)} <span class="who">${esc(l.account)} · ${esc(l.purpose)}${l.error ? ` · ${esc(l.error)}` : ''}</span></div>`;
}

async function renderScan(id) {
  const s = await api('GET', `/api/scans/${id}`);
  const isActive = ACTIVE.includes(s.status);
  const counts = Object.fromEntries(SEVERITIES.map((x) => [x, s.findings.filter((f) => f.severity === x).length]));
  const max = s.project.maxRequests || 1;
  const cmp = s.comparison;
  if (openState.filter && !s.findings.some((f) => f.severity === openState.filter)) openState.filter = null;
  const shown = visibleFindings(s);
  if (!shown.some((f) => f.id === openState.selected)) openState.selected = shown[0]?.id || null;
  const selected = s.findings.find((f) => f.id === openState.selected);
  const changeOf = (f) => (!cmp ? '' : cmp.new.some((x) => x.key === f.key) ? '<span class="chg st-running">new</span>' : '<span class="chg dim">still open</span>');
  const t0 = new Date(s.startedAt || s.createdAt);

  const prevList = document.querySelector('.flist ol');
  const listScroll = prevList?.scrollTop ?? 0;
  const prevLog = document.querySelector('#scanlog');
  const stickToBottom = !prevLog || prevLog.scrollTop + prevLog.clientHeight >= prevLog.scrollHeight - 24;
  const sameScan = view.name === 'scan' && view.id === id;

  view = { name: 'scan', id, scan: s };
  setShell({
    path: [{ label: 'projects', href: '#/' }, { label: slug(s.project.name), href: `#/p/${s.projectId}` }, { label: 'scans', href: `#/p/${s.projectId}/scans` }, { label: s.id, href: `#/s/${s.id}` }],
    windows: TABS.map(([key, label], n) => ({ n, label, href: `#/p/${s.projectId}/${key}`, current: key === 'scans' })),
    session: slug(s.project.name),
    right: `<span>${esc(s.status)} ${s.requestsSent}/${max}</span>`,
  });
  app.className = 'wide';
  app.innerHTML = `
    <section class="pane scanbar">
      <div class="ident">
        <h1>Scan ${status(s.status)}</h1>
        <div class="sub">${esc(s.id)} · ${fmtRange(s.startedAt || s.createdAt, s.finishedAt)}${s.previousScanId ? ' · retest' : ''}${s.startedBy ? ` · by ${esc(s.startedBy.email)}` : ''}</div>
      </div>
      <div class="meter" aria-label="Progress">
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="${max}" aria-valuenow="${s.requestsSent}"><div class="fill" id="fill"></div></div>
        <div class="checks"><span class="mono-num">${s.requestsSent}/${max} requests${s.writesSent ? ` · ${s.writesSent} writes` : ''}</span>${s.checks.filter((c) => c.id !== 'passive').map((c) => {
          const n = s.findings.filter((f) => f.check === c.id).length;
          const state = c.status === 'done' ? `${n} found` : c.status === 'running' ? 'running…' : c.status === 'not authorized' ? 'off' : c.status === 'incomplete' ? 'incomplete' : 'pending';
          return `<span class="${c.status === 'done' ? 'done' : c.status === 'running' ? 'run' : c.status === 'not authorized' ? 'off' : ''}" title="${esc(c.id)}: ${esc(state)}">${esc(c.id)} ${esc(c.status === 'done' ? String(n) : c.status === 'running' ? '…' : c.status === 'incomplete' ? '—' : '')}</span>`;
        }).join('')}</div>
      </div>
      <div class="tally" aria-label="Findings by severity">${SEVERITIES.map((x) => `<span class="${counts[x] ? `c-${x}` : 'zero'}"><b>${counts[x]}</b>${SEV_SHORT[x]}</span>`).join('')}</div>
      <div class="actions">
        ${s.status === 'running' ? '<button class="btn" id="pause" type="button">Pause <kbd>p</kbd></button>' : ''}
        ${s.status === 'paused' ? '<button class="btn primary" id="resume" type="button">Resume <kbd>p</kbd></button>' : ''}
        ${isActive ? '<button class="btn danger" id="stop" type="button">Stop <kbd>x</kbd></button>' : ''}
        ${!isActive && s.status !== 'blocked' ? `<a class="btn" id="report" href="/reports/${esc(s.id)}" target="_blank" rel="noopener">Report <kbd>o</kbd></a><a class="btn ghost" href="/api/scans/${esc(s.id)}/report.json">JSON</a><button class="btn primary" id="rerun" type="button">Retest <kbd>r</kbd></button>` : ''}
      </div>
    </section>
    ${!isActive && s.findings.length ? `<p class="next"><span class="dim">start with:</span> <a href="#" data-pick="${esc(s.findings[0].id)}">${tag(s.findings[0].severity)} ${esc(s.findings[0].title)}</a> <span class="dim">— fix the most severe finding first, then retest.</span></p>` : ''}
    ${s.stopReason ? `<p class="note warn"><b>Ended early.</b> ${esc(s.stopReason)}</p>` : ''}
    ${s.error ? `<p class="note bad"><b>Error.</b> ${esc(s.error)}</p>` : ''}
    ${s.problems ? `<div class="note bad"><b>Blocked.</b><ul>${s.problems.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}

    ${cmp ? `<section class="pane"><div class="pane-title"><h2>Retest</h2><span class="dim">compared with <a href="#/s/${esc(cmp.previousScanId)}">${esc(cmp.previousScanId)}</a></span>
        <span class="end"><span class="st-completed">${cmp.fixed.length} fixed</span> <span class="dim">·</span> <span class="c-medium">${cmp.stillOpen.length} still open</span> <span class="dim">·</span> <span class="st-running">${cmp.new.length} new</span>${cmp.unverified.length ? ` <span class="dim">· ${cmp.unverified.length} not re-checked</span>` : ''}</span></div>
      ${cmp.fixed.length ? `<div class="pane-body"><ul class="cmp">${cmp.fixed.map((f) => `<li><span class="k-fixed">fixed</span>${tag(f.severity)}<span>${esc(f.title)} <span class="dim">${esc(f.endpoint)}</span></span></li>`).join('')}</ul></div>` : ''}
    </section>` : ''}

    <div class="split">
      <div class="flist">
        <div class="pane-title"><span>Findings · ${shown.length}${openState.filter ? ` of ${s.findings.length}` : ''}</span><span><kbd>j</kbd> <kbd>k</kbd></span></div>
        ${s.findings.length > 5 ? `<div class="filters" role="group" aria-label="Filter by severity"><button type="button" class="chip" data-filter="" aria-pressed="${!openState.filter}">all ${s.findings.length}</button>${SEVERITIES.filter((x) => counts[x]).map((x) => `<button type="button" class="chip c-${x}" data-filter="${x}" aria-pressed="${openState.filter === x}">${SEV_SHORT[x]} ${counts[x]}</button>`).join('')}</div>` : ''}
        ${shown.length ? `<ol role="listbox" aria-label="Findings">${shown.map((f) => `<li role="none"><button class="fline" type="button" role="option" data-id="${esc(f.id)}" aria-selected="${f.id === openState.selected}">${tag(f.severity)}<span class="ft">${esc(f.title)}</span><span class="fe">${esc(f.endpoint)}${f.param ? ` · ${esc(f.param)}` : ''}${changeOf(f)}</span></button></li>`).join('')}</ol>` : `<p class="empty">${isActive ? 'Checks are running…' : 'Nothing to show.'}</p>`}
      </div>
      <div id="man">${manPage(s, selected)}</div>
    </div>

    <section class="pane"><div class="pane-title"><h2>Request log</h2><span class="dim">dmesg --follow · last ${s.log.length}</span></div>
      <div class="dmesg" id="scanlog">${s.log.map((l) => dmesgLine(l, t0)).join('')}</div>
    </section>`;

  fitFindingList();
  requestAnimationFrame(() => { document.getElementById('fill').style.width = `${Math.min(100, (s.requestsSent / max) * 100)}%`; });
  const list = document.querySelector('.flist ol');
  if (list && sameScan) list.scrollTop = listScroll;
  else document.querySelector('.fline[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  const log = document.getElementById('scanlog');
  if (stickToBottom || !sameScan) log.scrollTop = log.scrollHeight;

  document.querySelector('.filters')?.addEventListener('click', (e) => {
    const chip = e.target.closest('[data-filter]');
    if (!chip) return;
    openState.filter = chip.dataset.filter || null;
    renderScan(id);
  });
  document.querySelector('[data-pick]')?.addEventListener('click', (e) => {
    e.preventDefault();
    openState.filter = null;
    selectFinding(e.currentTarget.dataset.pick, true);
  });
  list?.addEventListener('click', (e) => {
    const btn = e.target.closest('.fline');
    if (btn) selectFinding(btn.dataset.id, false);
  });
  for (const action of ['pause', 'resume', 'stop']) {
    document.getElementById(action)?.addEventListener('click', (e) => scanAction(action, e.currentTarget));
  }
  document.getElementById('rerun')?.addEventListener('click', (e) => retest(e.currentTarget));

  clearInterval(pollTimer);
  if (isActive) pollTimer = setInterval(() => act(() => renderScan(id)), 1500);
}

/** Keeps the findings pane between its current top edge (or the sticky offset) and the fixed tmux bar. */
function fitFindingList() {
  const list = document.querySelector('.flist');
  if (!list) return;
  const bar = document.getElementById('tmux').offsetHeight;
  const top = Math.max(list.getBoundingClientRect().top, 46);
  list.style.setProperty('--flist-max', `${Math.max(280, window.innerHeight - bar - top - 12)}px`);
}
window.addEventListener('scroll', fitFindingList, { passive: true });
window.addEventListener('resize', fitFindingList);

function selectFinding(id, scrollIntoView) {
  if (view.name !== 'scan') return;
  const f = view.scan.findings.find((x) => x.id === id);
  if (!f) return;
  openState.selected = id;
  for (const b of document.querySelectorAll('.fline')) b.setAttribute('aria-selected', String(b.dataset.id === id));
  document.getElementById('man').innerHTML = manPage(view.scan, f);
  const btn = document.querySelector(`.fline[data-id="${CSS.escape(id)}"]`);
  if (scrollIntoView) btn?.scrollIntoView({ block: 'nearest' });
  btn?.focus({ preventScroll: true });
}

async function scanAction(action, trigger) {
  if (view.name !== 'scan') return;
  if (action === 'stop' && !await confirmDialog('Stop this scan now? Findings so far are kept.', 'Stop scan')) return;
  if (await act(() => api('POST', `/api/scans/${view.id}/${action}`), null, trigger)) renderScan(view.id);
}

async function retest(trigger) {
  if (view.name !== 'scan') return;
  const next = await act(() => api('POST', `/api/scans/${view.id}/rerun`), null, trigger);
  if (next) location.hash = `#/s/${next.id}`;
}

// ---------- Keyboard steering ----------

const keysDialog = document.getElementById('keys');
document.getElementById('help-btn').addEventListener('click', () => keysDialog.showModal());
document.getElementById('keys-close').addEventListener('click', () => keysDialog.close());

document.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || document.querySelector('dialog[open]')) return;
  if (e.target.closest('input, textarea, select, [contenteditable]')) return;
  const k = e.key;
  const projectId = view.name === 'project' ? view.id : view.name === 'scan' ? view.scan.projectId : null;
  let handled = true;
  if (k === '?') keysDialog.showModal();
  else if (/^[0-5]$/.test(k) && projectId) location.hash = `#/p/${projectId}/${TABS[Number(k)][0]}`;
  else if (k === 'u') {
    if (view.name === 'scan') location.hash = `#/p/${projectId}/scans`;
    else if (view.name === 'project') location.hash = '#/';
    else handled = false;
  } else if (k === 'n' && view.name === 'home') document.getElementById('pname')?.focus();
  else if (k === 's' && view.name === 'project' && view.tab === 'scans') document.getElementById('start')?.click();
  else if (view.name === 'scan' && (k === 'j' || k === 'k' || k === 'ArrowDown' || k === 'ArrowUp')) {
    const ids = visibleFindings(view.scan).map((f) => f.id);
    if (!ids.length) return;
    const i = ids.indexOf(openState.selected);
    const next = k === 'j' || k === 'ArrowDown' ? Math.min(ids.length - 1, i + 1) : Math.max(0, i - 1);
    selectFinding(ids[next], true);
  } else if (view.name === 'scan' && k === 'p') (document.getElementById('pause') || document.getElementById('resume'))?.click();
  else if (view.name === 'scan' && k === 'x') document.getElementById('stop')?.click();
  else if (view.name === 'scan' && k === 'r') document.getElementById('rerun')?.click();
  else if (view.name === 'scan' && k === 'o') document.getElementById('report')?.click();
  else handled = false;
  if (handled) e.preventDefault();
});

// ---------- Router ----------

function showBanner() {
  const b = document.getElementById('banner');
  b.innerHTML = me && !me.emailVerified ? `<p class="note warn"><b>Verify your email.</b> Until you do, you can look around but not create projects or run tests. <button class="btn sm" id="banner-resend" type="button">Resend link</button></p>` : '';
  document.getElementById('banner-resend')?.addEventListener('click', (e) => act(() => api('POST', '/api/auth/resend-verification'), 'Verification link sent — check your inbox', e.currentTarget));
}

async function route() {
  clearInterval(pollTimer);
  const hash = location.hash.slice(1) || '/';
  try {
    authInfo = await api('GET', '/api/auth/me');
  } catch (err) {
    guestShell('offline');
    app.innerHTML = guestPanel('Can’t reach the server', note('bad', esc(err.message)));
    return;
  }
  me = authInfo.user;
  let m;
  // Public pages work without a session (links from email).
  if ((m = hash.match(/^\/confirm\/([\w-]+)$/))) return renderConfirm(m[1]);
  if ((m = hash.match(/^\/verify\/([\w-]+)$/))) return renderVerify(m[1]);
  if ((m = hash.match(/^\/reset\/([\w-]+)$/))) return renderReset(m[1]);
  if ((m = hash.match(/^\/invite\/([\w-]+)$/))) return renderInvite(m[1]);
  if (authInfo.setupRequired) return renderSetup();
  if (hash === '/signup') return me ? (location.hash = '#/') : renderSignup();
  if (hash === '/forgot') return renderForgot();
  if (!me || hash === '/login') {
    if (me) return (location.hash = '#/');
    return renderLogin();
  }
  document.getElementById('logout').hidden = false;
  document.getElementById('nav-account').hidden = false;
  document.getElementById('nav-admin').hidden = me.role !== 'admin';
  showBanner();
  await act(async () => {
    if (hash === '/account') return renderAccount();
    if (hash === '/admin') return renderAdmin();
    if ((m = hash.match(/^\/p\/(\w+)(?:\/(\w+))?$/))) return renderProject(m[1], m[2]);
    if ((m = hash.match(/^\/s\/(\w+)$/))) {
      if (view.name !== 'scan' || view.id !== m[1]) openState.selected = null;
      return renderScan(m[1]);
    }
    return renderHome();
  });
  if (view.name !== 'scan') window.scrollTo(0, 0);
}

document.getElementById('logout').addEventListener('click', async () => {
  await api('POST', '/api/auth/logout').catch(() => {});
  me = null;
  location.hash = '#/login';
  route();
});
window.addEventListener('hashchange', route);
route();
