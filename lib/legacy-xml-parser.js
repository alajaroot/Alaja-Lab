'use strict';
const fs = require('fs');
const path = require('path');

// This module simulates an OUTDATED XML library that resolves external entities
// (the classic XXE vulnerability). Real modern XML parsers usually disable this
// by default; this one intentionally does not, to model A06 (using a vulnerable,
// outdated component) realistically without requiring an actual legacy dependency.

async function resolveEntity(systemId) {
  if (/^https?:\/\//i.test(systemId)) {
    const r = await fetch(systemId, { headers: { 'x-internal-fetch': 'lab-internal-1' } });
    return await r.text();
  }
  // Treat anything else as a local file path, relative to the project root.
  const filePath = path.resolve(process.cwd(), systemId.replace(/^file:\/\//i, ''));
  return fs.readFileSync(filePath, 'utf8');
}

// Parses <!DOCTYPE foo [ <!ENTITY name SYSTEM "target"> ... ]> and returns
// a map of entity name -> resolved content, plus the "body" XML with the
// DOCTYPE stripped out (entities are substituted into text nodes on demand).
async function parseWithExternalEntities(xml) {
  const entities = {};
  const doctypeMatch = xml.match(/<!DOCTYPE[^\[]*\[([\s\S]*?)\]>/i);
  if (doctypeMatch) {
    const entityDefs = doctypeMatch[1];
    const entityRegex = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/gi;
    let m;
    while ((m = entityRegex.exec(entityDefs)) !== null) {
      const [, name, systemId] = m;
      try {
        entities[name] = await resolveEntity(systemId);
      } catch (e) {
        entities[name] = `[[error resolving entity ${name}: ${e.message}]]`;
      }
    }
  }
  let body = xml.replace(/<!DOCTYPE[\s\S]*?\]>/i, '');
  // Substitute &name; references anywhere in the remaining document.
  for (const [name, value] of Object.entries(entities)) {
    body = body.split(`&${name};`).join(value);
  }
  return { xml: body, entities };
}

function extractTag(xml, tag) {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'i');
  const m = xml.match(re);
  return m ? m[1] : null;
}

module.exports = { parseWithExternalEntities, extractTag };
