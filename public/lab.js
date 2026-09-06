(function () {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  let challenge = null;
  const $ = (sel) => document.querySelector(sel);
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  async function loadChallenge() {
    const r = await fetch(`/api/lab/challenge/${encodeURIComponent(id)}`);
    if (!r.ok) { document.querySelector('main').innerHTML = '<p>Unknown objective. <a href="/">Back to dashboard</a>.</p>'; throw new Error('unknown'); }
    challenge = (await r.json()).challenge;
  }

  function renderHeader() {
    document.title = `${challenge.title} :: Objective`;
    $('#labHeader').innerHTML = `
      <div class="hero-top">
        <h1 class="hero-title"><span class="bracket">[${esc(challenge.category)}]</span> ${esc(challenge.title)}</h1>
        <span class="diff ${challenge.difficulty}" style="position:static">${challenge.difficulty}</span>
      </div>`;
    $('#labDesc').textContent = challenge.description;
  }

  function renderHints() {
    const area = $('#hintsArea');
    area.innerHTML = '';
    let next = 0;
    const btn = document.createElement('button');
    btn.className = 'hint-btn';
    btn.textContent = 'Reveal Hint';
    btn.addEventListener('click', async () => {
      const r = await fetch(`/api/lab/hint/${challenge.id}/${next}`);
      if (!r.ok) { btn.remove(); return; }
      const data = await r.json();
      const p = document.createElement('div');
      p.className = 'hint-text';
      p.textContent = `Hint ${next + 1}: ${data.hint}`;
      area.insertBefore(p, btn);
      next += 1;
      if (!data.hasMore) btn.remove();
    });
    area.appendChild(btn);
  }

  function renderWriteup() {
    const btn = $('#btnShowWriteup');
    const area = $('#writeupArea');
    const wu = challenge.writeup;
    if (!wu) { $('#writeupPanel').style.display = 'none'; return; }
    btn.addEventListener('click', () => {
      const showing = area.style.display !== 'none';
      if (showing) {
        area.style.display = 'none';
        btn.textContent = 'Show Full Solution';
      } else {
        area.innerHTML = `
          <div class="hint-text" style="font-weight:600">${esc(wu.cwe)}</div>
          <div class="hint-text"><b>Root cause:</b> ${esc(wu.rootCause)}</div>
          <div class="hint-text"><b>Impact:</b> ${esc(wu.impact)}</div>
          <div class="hint-text"><b>How it's exploited:</b> ${esc(wu.exploitSummary)}</div>
          <div class="hint-text"><b>Remediation:</b> ${esc(wu.remediation)}</div>
        `;
        area.style.display = 'block';
        btn.textContent = 'Hide Solution';
      }
    });
  }

  function setupFlagForm() {
    $('#flagForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const flag = $('#flagInput').value.trim();
      if (!flag) return;
      const r = await fetch('/api/lab/submit-flag', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ flag }) });
      const data = await r.json();
      const el = $('#flagResult');
      el.textContent = data.message || (data.correct ? 'Correct!' : 'Not correct — keep trying.');
      el.className = data.correct ? 'flag-ok' : 'flag-err';
      if (data.correct) {
        const rankLine = document.createElement('div');
        rankLine.className = 'flag-ok';
        rankLine.style.marginTop = '4px';
        rankLine.textContent = `Score: ${data.score}/${data.maxScore} — Rank: ${data.rank}`;
        el.after(rankLine);
      }
    });
  }

  (async function init() {
    if (!id) { document.querySelector('main').innerHTML = '<p>No objective specified. <a href="/">Back to dashboard</a>.</p>'; return; }
    await loadChallenge();
    renderHeader();
    renderHints();
    renderWriteup();
    setupFlagForm();
  })();
})();
