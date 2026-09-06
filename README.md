# OWASP Top 10 :: CTF Lab

A self-contained, local capture-the-flag lab covering the **OWASP Top 10 (2021)**, with three
difficulty tiers per category (Easy / Medium / Hard) — **30 challenges total**. Pure Node.js/Express,
no Docker, no native compiled dependencies (uses `sql.js`, a pure WASM SQLite build, for the real
SQL injection challenges).

Built for hands-on practice with Burp Suite, curl, and custom scripts — every challenge is a real,
working vulnerability in real server-side code, not a simulated/scripted "gotcha."

## Setup

```bash
npm install
npm start
```

Then open **http://localhost:4010** for the objectives dashboard. Port is configurable via `PORT=xxxx npm start`.

This isn't a single sandbox with 30 exploit buttons — it's one small, cohesive fake company site
("SecureCorp") with real navigation (Home, Directory, Shop, Support, Admin, Developer Portal, Account,
Settings) that hosts all 30 vulnerabilities as ordinary-looking features. Click **"Open Target
Application"** from the dashboard (or go straight to `/target.html`) and explore it like you would a real
assessment target: register/log in through its own Login/Register pages, click around the nav, use
features normally, and look for where things break.

Some things are deliberately **not** linked from the nav — a legacy admin panel only reachable via the
footer, a debug console only mentioned in `robots.txt`, an exposed backup file you have to guess the name
of. That's intentional: recon is part of the exercise.

Where a vulnerability lives in a visible form field (SQL injection, XSS, a malicious URL), you can exploit
it by typing directly into the real UI. Where a real app wouldn't expose the vulnerable parameter at all
(a spoofable header, a hidden price field, a JWT you need to forge, a `__proto__` key), the feature just
behaves normally in the UI — you're expected to intercept that request with Burp Suite (proxy your browser
through it) or your browser's DevTools Network tab and tamper with it there, exactly like real-world
testing. A few also need real tooling to finish (cracking an MD5 hash, forging a JWT, brute-forcing a
password list) — same as an actual test, not a built-in "solve" button.

The dashboard (`/`) is separate from the target app: it lists all 30 objectives with a short description,
progressive hints (click to reveal, deliberately light on specifics at first), a **points/rank tracker**,
and a flag box. It doesn't tell you which page to visit — that's for you to find.

## Scoring

Each objective is worth points by difficulty — Easy 15, Medium 30, Hard 55 — for **1000 points total**
across all 30. Your score and a rank title (Script Kiddie → Bug Hunter → Security Researcher → Senior
Pentester → Elite Researcher → OWASP Master) are shown on the dashboard and update live as you submit
correct flags.

## Write-ups

Every objective's detail page (`lab.html?id=...`) has a collapsed **"Solution & Write-up"** section —
click to reveal it any time, whether or not you've solved it yet. Each one covers the CWE classification,
root cause, real-world impact, how it's actually exploited, and concrete remediation — the kind of thing
you'd want on hand after a real assessment, not just a flag string.

Flags follow the format `LAB{...}` and are checked via `POST /api/lab/submit-flag`.

## How it's organized

```
server.js            - wires everything together, plus "internal-only" SSRF-target endpoints
lib/
  flags.js            - the master challenge registry: titles, descriptions, hints, flags
  db.js               - in-memory user directory shared by several challenges
  sqldb.js             - real in-memory SQLite (sql.js) used by the A03 SQLi challenges
  insecure-jwt.js      - deliberately insecure JWT sign/verify (trusts the token's own "alg")
  insecure-deserialize.js - node-serialize-style eval-based deserialization
  legacy-xml-parser.js - naive external-entity-resolving XML parser (models an outdated/XXE-prone lib)
  internal-state.js    - tracks whether a blind-SSRF target was actually reached
  session.js            - cookie-based session store (intentionally doesn't rotate IDs - see A07-medium)
routes/
  auth.js, lab.js       - shared login/register + flag submission/progress/hints
  a01.js ... a10.js     - one file per OWASP category, each with /easy /medium /hard routes
public/
  index.html, app.js    - the objectives dashboard (progress tracking, hints, flag submission)
  lab.html, lab.js       - a single objective's detail page (description + hints + flag box)
  target.html, target.js - the target application itself: a hash-routed single-page "SecureCorp"
                            site whose pages are where all 30 vulnerabilities actually live
  static/                 - files used by a couple of challenges (exposed backup, plugin hosting)
confidential/           - target files read by several file-read/RCE-style challenges
```

`target.js` is the one worth reading if you want the map: it defines every page of the fake site
(`/login`, `/directory`, `/shop`, `/admin`, `/developer`, etc.) and exactly which real endpoint each
page's form/button calls. Nothing in it reveals which page maps to which OWASP category — that's the
point.

Each `routes/aXX.js` file has inline `// VULN:` comments at the exact line that's broken, so once
you've solved (or given up on) a challenge you can open the source and see precisely what the flaw was
and why it works — this is meant to double as a mini code-review exercise, not just a black-box CTF.

## Challenge index

| # | Category | Easy | Medium | Hard |
|---|----------|------|--------|------|
| A01 | Broken Access Control | IDOR on profile lookup | Header-trust admin check | Mass assignment → role escalation |
| A02 | Cryptographic Failures | Base64 mistaken for encryption | Unsalted MD5 crack | JWT `alg:none` forgery |
| A03 | Injection | Classic SQLi login bypass | Blind boolean-based SQLi | OS command injection |
| A04 | Insecure Design | Brute-forceable coupon code | Client-trusted price | Predictable reset token |
| A05 | Security Misconfiguration | Leftover default creds | Exposed backup file | Undocumented debug console (RCE) |
| A06 | Vulnerable & Outdated Components | XXE | Insecure deserialization | XXE chained into SSRF |
| A07 | Auth Failures | No lockout / weak password | Session fixation | MFA step-skip logic flaw |
| A08 | Software & Data Integrity Failures | eval() cookie deserialization | Unsigned plugin load (RCE) | Prototype pollution → auth bypass |
| A09 | Logging & Monitoring Failures | Log injection (forged entry) | Stored XSS via log viewer | Unmonitored mass enumeration |
| A10 | SSRF | Unrestricted SSRF | Denylist bypass | Blind SSRF via webhook + open-redirect chain |

Full descriptions, exact endpoints, and progressive hints for each are in the dashboard UI (or
`lib/flags.js` if you'd rather read spoilers directly).

## Notes on a few deliberate simplifications

- **One real login endpoint carries three flaws at once**: `/api/a03/easy/login` is the site's actual
  Sign In form. It's SQL-injectable (A03-easy), has zero rate limiting so a weak account can be brute
  forced (A07-easy), and has a special-cased MFA branch for one account that turns out not to be checked
  properly downstream (A07-hard). This mirrors how a single real endpoint often has more than one
  independent problem — deliberately not three separate isolated endpoints.
- **A09-medium (stored XSS)**: there's no real headless browser wired in, so "the admin bot visiting
  the log page" is simulated server-side — your injected `<script>` body is extracted and executed
  in a small Node sandbox with a fake `document.cookie` and a real `fetch`, which reproduces the same
  exploit primitive (script injection → cookie exfiltration) without the overhead of a full browser
  automation stack.
- **A10 internal-only endpoints**: `/internal/*` routes require both a loopback source address *and*
  a marker header that only the lab's own outbound-fetch helpers attach. This is deliberately even
  stricter than most real "internal-only" targets, to guarantee the flag genuinely requires triggering
  a server-side request rather than just hitting the path directly in your browser (which, since
  everything runs on localhost, would otherwise also satisfy a naive IP-based check).
- **A06-hard / A10-hard**: these are the two chained challenges — XXE→SSRF and SSRF-via-open-redirect,
  respectively. If you've solved the earlier tiers in that category, the underlying primitive is the
  same; hard mode is about the chaining, not a new bug class.
- Flags are static/hardcoded per install so write-ups are reproducible across runs. Restarting the
  server resets all in-memory state (users you registered, logs you wrote, webhooks you registered,
  solved-progress) but not the flags themselves.

## Resetting

Everything is in-memory except the log files under `logs/`. To fully reset: stop the server, delete
`logs/`, and restart.
