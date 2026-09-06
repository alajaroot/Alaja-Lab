'use strict';
const express = require('express');
const router = express.Router();
const { publicChallengeList, publicChallenge, checkFlag, ID_TO_CHALLENGE, POINTS, MAX_SCORE, scoreForSolved, rankForScore } = require('../lib/flags');
const { ensurePlayer, progress } = require('../lib/session');

router.get('/challenges', (req, res) => {
  ensurePlayer(req, res);
  res.json({ challenges: publicChallengeList() });
});

router.get('/challenge/:id', (req, res) => {
  ensurePlayer(req, res);
  const c = publicChallenge(req.params.id);
  if (!c) return res.status(404).json({ error: 'unknown challenge' });
  res.json({ challenge: c });
});

router.get('/progress', (req, res) => {
  const pid = ensurePlayer(req, res);
  const solved = Array.from(progress.get(pid) || []);
  const score = scoreForSolved(solved);
  res.json({ solved, score, maxScore: MAX_SCORE, rank: rankForScore(score) });
});

router.post('/submit-flag', (req, res) => {
  const pid = ensurePlayer(req, res);
  const { flag } = req.body || {};
  const challenge = checkFlag(flag);
  if (!challenge) return res.status(400).json({ correct: false, message: 'Not a valid flag.' });
  const alreadySolved = progress.get(pid).has(challenge.id);
  progress.get(pid).add(challenge.id);
  const solved = Array.from(progress.get(pid));
  const score = scoreForSolved(solved);
  const points = POINTS[challenge.difficulty];
  res.json({
    correct: true,
    message: alreadySolved
      ? `Correct! (Already solved — ${challenge.title}.)`
      : `Correct! You solved ${challenge.title} (${challenge.category} - ${challenge.difficulty}) for +${points} points.`,
    challengeId: challenge.id,
    pointsAwarded: alreadySolved ? 0 : points,
    score, maxScore: MAX_SCORE, rank: rankForScore(score)
  });
});

router.get('/hint/:id/:index', (req, res) => {
  const c = ID_TO_CHALLENGE.get(req.params.id);
  if (!c) return res.status(404).json({ error: 'unknown challenge' });
  const idx = Number(req.params.index);
  if (Number.isNaN(idx) || idx < 0 || idx >= c.hints.length) {
    return res.status(404).json({ error: 'no more hints' });
  }
  res.json({ hint: c.hints[idx], hasMore: idx + 1 < c.hints.length });
});

module.exports = router;
