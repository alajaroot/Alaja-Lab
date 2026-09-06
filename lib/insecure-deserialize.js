'use strict';
// Mimics the real-world "node-serialize" vulnerability class (CVE-2017-5941 and friends):
// functions are encoded in the JSON as a special marker string, and the "deserializer"
// blindly eval()s that marker back into an invoked function. This is deliberately unsafe.

const FUNC_MARKER = '_$$ND_FUNC$$_';

function deserialize(serialized) {
  const raw = Buffer.from(serialized, 'base64').toString('utf8');
  const obj = JSON.parse(raw, (key, value) => {
    if (typeof value === 'string' && value.startsWith(FUNC_MARKER)) {
      const body = value.slice(FUNC_MARKER.length);
      // VULN: eval of attacker-controlled function source, then immediately invoked.
      // eslint-disable-next-line no-eval
      return eval(`(${body})`);
    }
    return value;
  });
  return obj;
}

module.exports = { deserialize, FUNC_MARKER };
