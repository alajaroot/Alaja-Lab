(function () {
  let challenges = [];
  let solved = new Set();
  let filter = 'all';
  let score = 0, maxScore = 1000, rank = 'Script Kiddie';

  const categoriesEl = document.getElementById('categories');
  const solvedCountEl = document.getElementById('solvedCount');
  const scoreLabelEl = document.getElementById('scoreLabel');
  const rankLabelEl = document.getElementById('rankLabel');
  const progressBarEl = document.getElementById('progressBar');

  function toast(msg, ok) {
    const el = document.createElement('div');
    el.className = 'toast ' + (ok ? 'ok' : 'err');
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  async function loadChallenges() {
    const r = await fetch('/api/lab/challenges');
    const data = await r.json();
    challenges = data.challenges;
  }

  async function loadProgress() {
    const r = await fetch('/api/lab/progress');
    const data = await r.json();
    solved = new Set(data.solved);
    score = data.score; maxScore = data.maxScore; rank = data.rank;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function updateMeter() {
    solvedCountEl.textContent = solved.size;
    scoreLabelEl.textContent = score;
    rankLabelEl.textContent = `Rank: ${rank}`;
    progressBarEl.style.width = Math.round((score / maxScore) * 100) + '%';
  }

  function matchesFilter(c) {
    if (filter === 'all') return true;
    if (filter === 'unsolved') return !solved.has(c.id);
    return c.difficulty === filter;
  }

  function render() {
    const byCategory = {};
    for (const c of challenges) {
      if (!byCategory[c.category]) byCategory[c.category] = { name: c.name, items: [] };
      byCategory[c.category].items.push(c);
    }
    const categoryIds = Object.keys(byCategory).sort();
    categoriesEl.innerHTML = '';
    for (const catId of categoryIds) {
      const cat = byCategory[catId];
      const visible = cat.items.filter(matchesFilter);
      if (visible.length === 0) continue;
      const block = document.createElement('div');
      block.className = 'category-block';
      block.innerHTML = `<div class="category-head"><span class="id">${catId}</span><span class="name">${escapeHtml(cat.name)}</span><span class="line"></span></div>`;
      const grid = document.createElement('div');
      grid.className = 'grid';
      for (const c of visible.sort((a, b) => diffRank(a.difficulty) - diffRank(b.difficulty))) {
        grid.appendChild(renderCard(c));
      }
      block.appendChild(grid);
      categoriesEl.appendChild(block);
    }
  }

  function diffRank(d) { return d === 'easy' ? 0 : d === 'medium' ? 1 : 2; }

  function renderCard(c) {
    const isSolved = solved.has(c.id);
    const pts = { easy: 15, medium: 30, hard: 55 }[c.difficulty];
    const card = document.createElement('div');
    card.className = 'card' + (isSolved ? ' solved' : '');
    card.innerHTML = `
      <span class="diff ${c.difficulty}">${c.difficulty} · ${pts}pt</span>
      <h3>${escapeHtml(c.title)}</h3>
      <p class="desc">${escapeHtml(c.description)}</p>
      ${isSolved ? '<div class="solved-tag">flag captured</div>' : ''}
      <a class="open-lab" href="/lab.html?id=${encodeURIComponent(c.id)}">${isSolved ? 'View Write-up →' : 'View Objective →'}</a>
    `;
    return card;
  }

  document.getElementById('filterRow').addEventListener('click', (e) => {
    if (e.target.tagName !== 'BUTTON') return;
    filter = e.target.dataset.filter;
    [...document.querySelectorAll('#filterRow button')].forEach(b => b.classList.toggle('active', b === e.target));
    render();
  });

  (async function init() {
    await Promise.all([loadChallenges(), loadProgress()]);
    updateMeter();
    render();
  })();
})();
