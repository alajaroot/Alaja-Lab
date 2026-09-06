(function () {
  function port() { return location.port || '4010'; }
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  const $ = (root, sel) => root.querySelector(sel);

  async function api(method, path, body, headers) {
    const opts = { method, credentials: 'include', headers: headers || {} };
    if (body !== undefined && body !== null) opts.body = body;
    let status, text;
    try {
      const r = await fetch(path, opts);
      status = r.status;
      text = await r.text();
    } catch (e) { status = 'ERR'; text = String(e); }
    return { status, text };
  }
  function pretty(t) { try { return JSON.stringify(JSON.parse(t), null, 2); } catch (e) { return t; } }
  function resultHtml(status, text, kind) {
    if (!kind) kind = (status >= 200 && status < 300) ? 'success' : 'error';
    return `<div class="result-box ${kind}">HTTP ${esc(String(status))}\n${esc(pretty(text))}</div>`;
  }
  function extractFlag(text) { const m = String(text).match(/LAB\{[^}]+\}/); return m ? m[0] : null; }

  let currentUser = null;
  async function refreshUser() {
    const r = await fetch('/api/auth/me');
    const d = await r.json();
    currentUser = d.user;
    return currentUser;
  }

  // ---------------- Nav ----------------
  function renderNav(currentPath) {
    const links = [
      ['/', 'SecureCorp'], // brand, handled specially
      ['/directory', 'Directory'],
      ['/shop', 'Shop'],
      ['/support', 'Support'],
      ['/developer', 'Developer'],
      ['/admin', 'Admin'],
    ];
    let html = `<a class="brand" href="#/">🔒 SecureCorp</a>`;
    for (const [path, label] of links.slice(1)) {
      html += `<a class="nav-link ${currentPath === path ? 'current' : ''}" href="#${path}">${label}</a>`;
    }
    html += `<span class="spacer"></span>`;
    if (currentUser) {
      html += `<span class="nav-auth"><a href="#/account">${esc(currentUser.username)}</a> · <a href="#" id="navLogout">Log out</a></span>`;
    } else {
      html += `<span class="nav-auth"><a href="#/login">Log In</a> · <a href="#/register">Register</a></span>`;
    }
    document.getElementById('siteNav').innerHTML = html;
    const lo = document.getElementById('navLogout');
    if (lo) lo.addEventListener('click', async (e) => { e.preventDefault(); await api('POST', '/api/auth/logout'); location.hash = '#/'; });
  }

  // ---------------- Page renderers ----------------
  const PAGES = {};

  PAGES['/'] = {
    html: () => `
      <h1 class="page-title">Welcome to SecureCorp</h1>
      <p class="page-lede">Your one-stop portal for account management, shopping, and internal tools.</p>
      <div class="site-grid">
        <div class="site-card"><h3>Employee Directory</h3><p class="card-lede">Look up colleagues by name or ID.</p><a href="#/directory">Open Directory →</a></div>
        <div class="site-card"><h3>Shop</h3><p class="card-lede">Browse products, search, and redeem coupons.</p><a href="#/shop">Open Shop →</a></div>
        <div class="site-card"><h3>Support</h3><p class="card-lede">Submit tickets and browse community comments.</p><a href="#/support">Open Support →</a></div>
        <div class="site-card"><h3>Developer Portal</h3><p class="card-lede">API tokens, plugins, webhooks, and internal tools.</p><a href="#/developer">Open Developer Portal →</a></div>
      </div>
      <div class="site-card" style="max-width:420px">
        <h3>Newsletter</h3>
        <p class="card-lede">Get product updates in your inbox.</p>
        <input type="text" id="newsletterEmail" placeholder="you@example.com" />
        <button class="app-btn ghost" id="btnSubscribe">Subscribe</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSubscribe').addEventListener('click', () => {
        $(root, '#out').innerHTML = `<div class="result-box success">Subscribed! (this form doesn't do anything else — it's just a mailing list signup)</div>`;
      });
    }
  };

  PAGES['/login'] = {
    html: () => `
      <h1 class="page-title">Sign In</h1>
      <div class="site-card" style="max-width:380px">
        <label>Username</label><input type="text" id="u" />
        <label>Password</label><input type="password" id="p" />
        <button class="app-btn" id="btnLogin">Log In</button>
        <p style="font-size:12.5px;margin-top:10px"><a href="#/forgot-password">Forgot password?</a> · <a href="#/register">Create an account</a></p>
        <div id="out"></div>
      </div>
      <div id="mfaCard" class="site-card" style="max-width:380px; display:none">
        <h3>Verification Required</h3>
        <p class="card-lede">Enter the 6-digit code sent to this account's device.</p>
        <label>Verification code</label><input type="text" id="otp" />
        <button class="app-btn secondary" id="btnVerify">Verify</button>
        <div id="mfaOut"></div>
      </div>
    `,
    wire(root) {
      let pendingToken = null;
      $(root, '#btnLogin').addEventListener('click', async () => {
        const body = JSON.stringify({ username: $(root, '#u').value, password: $(root, '#p').value });
        const { status, text } = await api('POST', '/api/a03/easy/login', body, { 'Content-Type': 'application/json' });
        let data = {};
        try { data = JSON.parse(text); } catch (e) {}
        if (data.mfaRequired) {
          pendingToken = data.token;
          $(root, '#out').innerHTML = `<div class="result-box neutral">Password correct. Verification required.</div>`;
          $(root, '#mfaCard').style.display = 'block';
        } else {
          $(root, '#out').innerHTML = resultHtml(status, text);
        }
        window.__lastFlag = extractFlag(text);
      });
      $(root, '#btnVerify').addEventListener('click', async () => {
        // Real flow: verify-otp with the real code (which you don't have). Some apps'
        // "logged in" resource checks turn out not to actually require that step to have succeeded...
        const { status, text } = await api('GET', '/api/a07/hard/admin-flag', null, { 'Authorization': 'Bearer ' + (pendingToken || '') });
        $(root, '#mfaOut').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/register'] = {
    html: () => `
      <h1 class="page-title">Create an Account</h1>
      <div class="site-card" style="max-width:380px">
        <label>Username</label><input type="text" id="u" />
        <label>Password</label><input type="password" id="p" />
        <button class="app-btn" id="btnReg">Register</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnReg').addEventListener('click', async () => {
        const body = JSON.stringify({ username: $(root, '#u').value, password: $(root, '#p').value });
        const { status, text } = await api('POST', '/api/auth/register', body, { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text, status < 300 ? 'success' : 'error');
        if (status < 300) { await refreshUser(); renderNav('/register'); }
      });
    }
  };

  PAGES['/forgot-password'] = {
    html: () => `
      <h1 class="page-title">Forgot Password</h1>
      <div class="site-card" style="max-width:420px">
        <label>Username</label><input type="text" id="u" value="admin" />
        <button class="app-btn" id="btnSend">Send Reset Link</button>
        <div id="out1"></div>
      </div>
      <div class="site-card" style="max-width:420px">
        <h3>Reset Password</h3>
        <label>Username</label><input type="text" id="u2" value="admin" />
        <label>Reset token</label><input type="text" id="tok" placeholder="from your reset email (or figure out how it's generated)" />
        <label>New password</label><input type="text" id="np" value="new-password-123" />
        <button class="app-btn secondary" id="btnReset">Reset Password</button>
        <div id="out2"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSend').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a04/hard/forgot-password', JSON.stringify({ username: $(root, '#u').value }), { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnReset').addEventListener('click', async () => {
        const body = JSON.stringify({ username: $(root, '#u2').value, token: $(root, '#tok').value.trim(), newPassword: $(root, '#np').value });
        const { status, text } = await api('POST', '/api/a04/hard/reset-password', body, { 'Content-Type': 'application/json' });
        $(root, '#out2').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/directory'] = {
    html: () => `
      <h1 class="page-title">Employee Directory</h1>
      <p class="page-lede">Search for a colleague, or browse by ID.</p>
      <div class="site-card">
        <div class="profile-card"><span>Alice — QA Engineer</span><span class="pid">ID 1</span></div>
        <div class="profile-card"><span>Bob — Backend Dev</span><span class="pid">ID 2</span></div>
      </div>
      <div class="site-card">
        <label>Look up by employee ID</label>
        <input type="text" id="idInput" value="1" />
        <button class="app-btn" id="btnView">View Profile</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnView').addEventListener('click', async () => {
        const id = $(root, '#idInput').value.trim() || '1';
        const { status, text } = await api('GET', `/api/a01/easy/profile/${encodeURIComponent(id)}`);
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/account'] = {
    html: () => currentUser ? `
      <h1 class="page-title">My Account</h1>
      <p class="page-lede">Signed in as ${esc(currentUser.username)} (role: ${esc(currentUser.role)}).</p>
      <ul class="site-link-list">
        <li><a href="#/account/edit">Edit Profile</a><div class="item-desc">Update your bio and settings.</div></li>
        <li><a href="#/account/preferences">Preferences</a><div class="item-desc">Theme and display settings.</div></li>
        <li><a href="#/account/avatar">Profile Picture</a><div class="item-desc">Set an avatar from a URL.</div></li>
        <li><a href="#/account/share">Share Access</a><div class="item-desc">Invite a teammate into your session.</div></li>
      </ul>
    ` : `<h1 class="page-title">My Account</h1><p class="page-lede">Please <a href="#/login">log in</a> to view your account.</p>`,
    wire() {}
  };

  PAGES['/account/edit'] = {
    html: () => `
      <h1 class="page-title">Edit Profile</h1>
      <div class="site-card" style="max-width:460px">
        <label>Bio</label>
        <textarea id="bio" rows="2">Just a researcher.</textarea>
        <button class="app-btn" id="btnSave">Save Changes</button>
        <div id="out1"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <button class="app-btn ghost" id="btnCheck">Check Admin Access</button>
        <div id="out2"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSave').addEventListener('click', async () => {
        const { status, text } = await api('PATCH', '/api/a01/hard/profile', JSON.stringify({ bio: $(root, '#bio').value }), { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCheck').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a01/hard/admin-flag');
        $(root, '#out2').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/account/preferences'] = {
    html: () => `
      <h1 class="page-title">Preferences</h1>
      <div class="site-card" style="max-width:420px">
        <label>Theme</label>
        <select id="theme"><option>dark</option><option>light</option></select>
        <button class="app-btn" id="btnLoad">Load My Preferences</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnLoad').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a08/easy/prefs');
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/account/avatar'] = {
    html: () => `
      <h1 class="page-title">Profile Picture</h1>
      <div class="site-card" style="max-width:460px">
        <label>Avatar URL</label>
        <input type="text" id="url" value="https://example.com" />
        <button class="app-btn" id="btnFetch">Fetch &amp; Preview</button>
        <div id="out"></div>
      </div>
      <p style="font-size:13px"><a href="#/account/avatar-v2">Try our new avatar fetcher (beta) →</a></p>
    `,
    wire(root) {
      $(root, '#btnFetch').addEventListener('click', async () => {
        const url = $(root, '#url').value.trim();
        const { status, text } = await api('POST', '/api/a10/easy/fetch-avatar', JSON.stringify({ url }), { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text, 'neutral');
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/account/avatar-v2'] = {
    html: () => `
      <h1 class="page-title">Profile Picture <span class="badge-pill">beta — now with SSRF protection</span></h1>
      <div class="site-card" style="max-width:460px">
        <label>Avatar URL</label>
        <input type="text" id="url" value="https://example.com" />
        <button class="app-btn" id="btnFetch">Fetch &amp; Preview</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnFetch').addEventListener('click', async () => {
        const url = $(root, '#url').value.trim();
        const { status, text } = await api('POST', '/api/a10/medium/fetch-avatar-v2', JSON.stringify({ url }), { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text, 'neutral');
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/account/share'] = {
    html: () => `
      <h1 class="page-title">Share Access</h1>
      <p class="page-lede">Generate a link that brings a teammate into your current session.</p>
      <div class="site-card" style="max-width:460px">
        <label>Session id for this link</label>
        <input type="text" id="sid" value="attacker-chosen-123" />
        <button class="app-btn" id="btnGen">Generate Link</button>
        <div id="out1"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <label>Simulate: a teammate opens your link and signs in</label>
        <button class="app-btn secondary" id="btnVisit">Simulate Teammate Sign-In</button>
        <div id="out2"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <button class="app-btn ghost" id="btnCheck">Check My Access</button>
        <div id="out3"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnGen').addEventListener('click', async () => {
        const sid = $(root, '#sid').value.trim();
        const { status, text } = await api('GET', `/api/a07/medium/set-session?sid=${encodeURIComponent(sid)}`);
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnVisit').addEventListener('click', async () => {
        const sid = $(root, '#sid').value.trim();
        const { status, text } = await api('POST', '/api/a07/medium/admin-visits-link', JSON.stringify({ sid }), { 'Content-Type': 'application/json' });
        $(root, '#out2').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCheck').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a07/medium/flag');
        $(root, '#out3').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/shop'] = {
    html: () => `
      <h1 class="page-title">Shop</h1>
      <div class="site-card">
        <label>Search products</label>
        <input type="text" id="q" value="Mouse" />
        <button class="app-btn" id="btnSearch">Search</button>
        <div id="out"></div>
      </div>
      <div class="site-grid">
        <div class="site-card"><h3>Premium Widget</h3><p class="card-lede">$499.99</p><a href="#/shop/product">View Product →</a></div>
        <div class="site-card"><h3>Have a coupon?</h3><p class="card-lede">Redeem a discount code.</p><a href="#/shop/coupon">Redeem →</a></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSearch').addEventListener('click', async () => {
        const q = $(root, '#q').value;
        const { text } = await api('GET', `/api/a03/medium/search?name=${encodeURIComponent(q)}`);
        let msg = 'Search failed.';
        try { msg = JSON.parse(text).found ? '1 result found.' : 'No results found.'; } catch (e) {}
        $(root, '#out').innerHTML = `<div class="result-box neutral">${esc(msg)}</div>`;
      });
    }
  };

  PAGES['/shop/product'] = {
    html: () => `
      <h1 class="page-title">Premium Widget</h1>
      <div class="site-card" style="max-width:420px">
        <p class="card-lede">$499.99 — free shipping.</p>
        <button class="app-btn" id="btnBuy">Buy Now</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnBuy').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a04/medium/checkout', JSON.stringify({ itemId: 1, price: 499.99 }), { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/shop/coupon'] = {
    html: () => `
      <h1 class="page-title">Redeem Coupon</h1>
      <div class="site-card" style="max-width:360px">
        <label>Coupon code</label>
        <input type="text" id="code" value="0000" maxlength="4" />
        <button class="app-btn" id="btnRedeem">Redeem</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnRedeem').addEventListener('click', async () => {
        const code = $(root, '#code').value.trim();
        const { status, text } = await api('GET', `/api/a04/easy/redeem?code=${encodeURIComponent(code)}`);
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/support'] = {
    html: () => `
      <h1 class="page-title">Support</h1>
      <div class="site-card">
        <label>Describe your issue</label>
        <textarea id="msg" rows="2">Having trouble logging in.</textarea>
        <button class="app-btn" id="btnSubmit">Submit Ticket</button>
        <div id="out1"></div>
      </div>
      <div class="site-card">
        <label>Admin: check system alerts</label>
        <button class="app-btn ghost" id="btnCheck">Check System Alerts</button>
        <div id="out2"></div>
      </div>
      <p style="font-size:13px"><a href="#/support/community">Browse community comments →</a></p>
    `,
    wire(root) {
      $(root, '#btnSubmit').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a09/easy/log', JSON.stringify({ msg: $(root, '#msg').value }), { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCheck').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a09/easy/check-log');
        $(root, '#out2').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/support/community'] = {
    html: () => `
      <h1 class="page-title">Community Comments</h1>
      <div class="site-card">
        <label>Leave a comment</label>
        <textarea id="msg" rows="2">Nice site!</textarea>
        <button class="app-btn" id="btnPost">Post</button>
        <div id="out1"></div>
      </div>
      <div class="site-card">
        <label>Preview rendering</label>
        <button class="app-btn ghost" id="btnPreview">Preview</button>
        <iframe class="preview-frame" id="previewFrame" style="display:none"></iframe>
      </div>
      <div class="site-card">
        <label>Simulate: an admin reviews the comments</label>
        <button class="app-btn secondary" id="btnBot">Simulate Admin Review</button>
        <div id="out2"></div>
      </div>
      <div class="site-card">
        <label>Check what your collection endpoint received</label>
        <button class="app-btn ghost" id="btnCollected">View Collected Data</button>
        <div id="out3"></div>
      </div>
      <div class="site-card">
        <label>Use a captured admin cookie</label>
        <input type="text" id="cookie" placeholder="paste captured cookie value here" />
        <button class="app-btn secondary" id="btnFlag">Access Admin Panel</button>
        <div id="out4"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnPost').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a09/medium/log', JSON.stringify({ msg: $(root, '#msg').value }), { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnPreview').addEventListener('click', async () => {
        const { text } = await api('GET', '/api/a09/medium/view-log');
        const frame = $(root, '#previewFrame');
        frame.style.display = 'block';
        frame.srcdoc = text;
      });
      $(root, '#btnBot').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a09/medium/trigger-bot');
        $(root, '#out2').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCollected').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a09/medium/collected');
        $(root, '#out3').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnFlag').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a09/medium/flag', null, { 'X-Admin-Cookie': $(root, '#cookie').value.trim() });
        $(root, '#out4').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/admin'] = {
    html: () => `
      <h1 class="page-title">Admin Console</h1>
      <p class="page-lede">Staff-only area.</p>
      <div class="site-card">
        <button class="app-btn" id="btnGo">Open Admin Console</button>
        <div id="out"></div>
      </div>
      <ul class="site-link-list">
        <li><a href="#/admin/reports">Reports — Import (Legacy XML)</a></li>
        <li><a href="#/admin/export">Data Export</a></li>
      </ul>
    `,
    wire(root) {
      $(root, '#btnGo').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a01/medium/admin/users');
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/admin/reports'] = {
    html: () => `
      <h1 class="page-title">Admin Reports — Import (Legacy XML)</h1>
      <div class="site-card">
        <label>Paste XML</label>
        <textarea id="xml" rows="4">&lt;root&gt;&lt;data&gt;hello&lt;/data&gt;&lt;/root&gt;</textarea>
        <button class="app-btn" id="btnImport">Import</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnImport').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a06/hard/import-xml', $(root, '#xml').value, { 'Content-Type': 'application/xml' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/admin/export'] = {
    html: () => `
      <h1 class="page-title">Data Export</h1>
      <div class="site-card" style="max-width:360px">
        <label>Page</label>
        <input type="text" id="page" value="1" />
        <button class="app-btn" id="btnView">View Page</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnView').addEventListener('click', async () => {
        const page = $(root, '#page').value.trim();
        const { status, text } = await api('GET', `/api/a09/hard/export?page=${encodeURIComponent(page)}`);
        $(root, '#out').innerHTML = resultHtml(status, text, 'neutral');
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer'] = {
    html: () => `
      <h1 class="page-title">Developer Portal</h1>
      <ul class="site-link-list">
        <li><a href="#/developer/tokens">API Access Tokens</a></li>
        <li><a href="#/developer/plugins">Plugin Marketplace</a></li>
        <li><a href="#/developer/webhooks">Webhooks</a></li>
        <li><a href="#/developer/import">Data Import (XML)</a></li>
        <li><a href="#/developer/restore-session">Restore Saved Session</a></li>
        <li><a href="#/developer/internal-tools">Internal Tools</a></li>
        <li><a href="#/developer/network-tools">Network Diagnostics</a></li>
        <li><a href="#/developer/changelog">API Changelog</a></li>
      </ul>
    `,
    wire() {}
  };

  PAGES['/developer/changelog'] = {
    html: () => `
      <h1 class="page-title">API Changelog</h1>
      <div class="site-card">
        <h3>v2.3.0</h3><p class="card-lede">Added webhook retry logic. Fixed pagination bug in exports.</p>
        <h3>v2.2.0</h3><p class="card-lede">Deprecated the legacy /v1/session endpoints.</p>
        <h3>v2.1.0</h3><p class="card-lede">Introduced the plugin marketplace.</p>
      </div>
      <p class="muted">Just release notes — nothing interactive on this page.</p>
    `,
    wire() {}
  };

  PAGES['/developer/tokens'] = {
    html: () => `
      <h1 class="page-title">API Access Tokens</h1>
      <div class="site-card" style="max-width:460px">
        <button class="app-btn" id="btnGen">Generate Token</button>
        <div id="out1"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <label>Access token</label>
        <input type="text" id="tok" />
        <button class="app-btn secondary" id="btnUse">Access Admin Resource</button>
        <div id="out2"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnGen').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a02/hard/token');
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
        try { $(root, '#tok').value = JSON.parse(text).token; } catch (e) {}
      });
      $(root, '#btnUse').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a02/hard/admin', null, { 'Authorization': 'Bearer ' + $(root, '#tok').value.trim() });
        $(root, '#out2').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/plugins'] = {
    html: () => `
      <h1 class="page-title">Plugin Marketplace</h1>
      <div class="site-card" style="max-width:460px">
        <label>Plugin URL</label>
        <input type="text" id="url" placeholder="http://127.0.0.1:4010/static/my-plugin.js" />
        <button class="app-btn" id="btnInstall">Install</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnInstall').addEventListener('click', async () => {
        const url = $(root, '#url').value.trim();
        const { status, text } = await api('POST', '/api/a08/medium/install-plugin', JSON.stringify({ url }), { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/webhooks'] = {
    html: () => `
      <h1 class="page-title">Webhooks</h1>
      <div class="site-card" style="max-width:460px">
        <label>Webhook URL</label>
        <input type="text" id="url" value="https://example.com/webhook" />
        <button class="app-btn" id="btnSave">Save Webhook</button>
        <div id="out1"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <button class="app-btn secondary" id="btnFire">Send Test Event</button>
        <div id="out2"></div>
      </div>
      <div class="site-card" style="max-width:460px">
        <button class="app-btn ghost" id="btnCheck">View Delivery Status</button>
        <div id="out3"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSave').addEventListener('click', async () => {
        const url = $(root, '#url').value.trim();
        const { status, text } = await api('POST', '/api/a10/hard/register-webhook', JSON.stringify({ url }), { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnFire').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a10/hard/fire-webhook');
        $(root, '#out2').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCheck').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a10/hard/check-flag');
        $(root, '#out3').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/import'] = {
    html: () => `
      <h1 class="page-title">Data Import (XML)</h1>
      <div class="site-card">
        <label>Paste XML</label>
        <textarea id="xml" rows="4">&lt;root&gt;&lt;data&gt;hello&lt;/data&gt;&lt;/root&gt;</textarea>
        <button class="app-btn" id="btnImport">Import</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnImport').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a06/easy/import-xml', $(root, '#xml').value, { 'Content-Type': 'application/xml' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/restore-session'] = {
    html: () => `
      <h1 class="page-title">Restore a Saved Session</h1>
      <div class="site-card">
        <label>Session blob (base64)</label>
        <textarea id="blob" rows="3">eyJmb28iOiJiYXIifQ==</textarea>
        <button class="app-btn" id="btnRestore">Restore</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnRestore').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a06/medium/import-session', JSON.stringify({ blob: $(root, '#blob').value.trim() }), { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/internal-tools'] = {
    html: () => `
      <h1 class="page-title">Internal Tools</h1>
      <div class="site-card">
        <h3>Export Recovery Codes</h3>
        <button class="app-btn ghost" id="btnExport">Export</button>
        <div id="out1"></div>
      </div>
      <div class="site-card">
        <h3>Leaked Hash Dump (internal diagnostic)</h3>
        <button class="app-btn ghost" id="btnLeak">View</button>
        <div id="out2"></div>
      </div>
      <div class="site-card" style="max-width:420px">
        <h3>Admin Login (legacy backend)</h3>
        <label>Username</label><input type="text" id="u" value="admin" />
        <label>Password</label><input type="password" id="p" />
        <button class="app-btn secondary" id="btnLogin">Log In</button>
        <div id="out3"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnExport').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a02/easy/users');
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
        try {
          const data = JSON.parse(text);
          for (const u of data.users || []) {
            if (u.recoveryCode) { try { const dec = atob(u.recoveryCode); if (/LAB\{/.test(dec)) window.__lastFlag = dec.match(/LAB\{[^}]+\}/)[0]; } catch (e) {} }
          }
        } catch (e) {}
      });
      $(root, '#btnLeak').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a02/medium/leak');
        $(root, '#out2').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnLogin').addEventListener('click', async () => {
        const body = JSON.stringify({ username: $(root, '#u').value, password: $(root, '#p').value });
        const { status, text } = await api('POST', '/api/a02/medium/login', body, { 'Content-Type': 'application/json' });
        $(root, '#out3').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/developer/network-tools'] = {
    html: () => `
      <h1 class="page-title">Network Diagnostics</h1>
      <div class="site-card" style="max-width:420px">
        <label>Host</label>
        <input type="text" id="host" value="127.0.0.1" />
        <button class="app-btn" id="btnPing">Ping</button>
        <pre id="out" class="result-box neutral" style="display:none"></pre>
      </div>
    `,
    wire(root) {
      $(root, '#btnPing').addEventListener('click', async () => {
        const host = $(root, '#host').value;
        const box = $(root, '#out'); box.style.display = 'block'; box.textContent = 'pinging...';
        const { text } = await api('POST', '/api/a03/hard/ping', JSON.stringify({ host }), { 'Content-Type': 'application/json' });
        let out = text;
        try { const d = JSON.parse(text); out = `$ ${d.command}\n${d.stdout || ''}${d.stderr || ''}`; } catch (e) {}
        box.textContent = out;
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/settings'] = {
    html: () => `
      <h1 class="page-title">Advanced Settings</h1>
      <div class="site-card">
        <label>Settings JSON</label>
        <textarea id="json" rows="3">{"theme": "dark"}</textarea>
        <button class="app-btn" id="btnSave">Save Settings</button>
        <div id="out1"></div>
      </div>
      <div class="site-card">
        <button class="app-btn ghost" id="btnCheck">Check Admin Access</button>
        <div id="out2"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnSave').addEventListener('click', async () => {
        const { status, text } = await api('POST', '/api/a08/hard/update-settings', $(root, '#json').value, { 'Content-Type': 'application/json' });
        $(root, '#out1').innerHTML = resultHtml(status, text, 'neutral');
      });
      $(root, '#btnCheck').addEventListener('click', async () => {
        const { status, text } = await api('GET', '/api/a08/hard/admin-flag');
        $(root, '#out2').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  PAGES['/legacy-admin'] = {
    html: () => `
      <h1 class="page-title" style="color:#8a6d00">⚠ Legacy Admin Panel <span class="badge-pill">deprecated 2019</span></h1>
      <div class="site-card" style="max-width:380px">
        <label>Username</label><input type="text" id="u" value="admin" />
        <label>Password</label><input type="password" id="p" />
        <button class="app-btn" id="btnLogin">Log In</button>
        <div id="out"></div>
      </div>
    `,
    wire(root) {
      $(root, '#btnLogin').addEventListener('click', async () => {
        const body = JSON.stringify({ username: $(root, '#u').value, password: $(root, '#p').value });
        const { status, text } = await api('POST', '/api/a05/easy/legacy-login', body, { 'Content-Type': 'application/json' });
        $(root, '#out').innerHTML = resultHtml(status, text);
        window.__lastFlag = extractFlag(text);
      });
    }
  };

  // ---------------- Router ----------------
  async function route() {
    const path = location.hash.slice(1) || '/';
    await refreshUser();
    renderNav(path);
    const page = PAGES[path];
    const main = document.getElementById('siteMain');
    if (!page) {
      main.innerHTML = `<h1 class="page-title">Not Found</h1><p class="page-lede">Nothing here. <a href="#/">Go home</a>.</p>`;
      return;
    }
    main.innerHTML = page.html();
    page.wire(main);
  }

  window.addEventListener('hashchange', route);
  route();
})();
