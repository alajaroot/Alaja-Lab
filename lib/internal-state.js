'use strict';
const hits = new Set();
function markHit(id) { hits.add(id); }
function wasHit(id) { return hits.has(id); }
module.exports = { markHit, wasHit };
