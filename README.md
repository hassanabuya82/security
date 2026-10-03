# [Autoswagger](https://www.intruder.io/research/broken-authorization-apis-autoswagger) by [Intruder](https://intruder.io/)
<a href="https://intruder.io/">
  <img width="966" alt="output" src="https://github.com/user-attachments/assets/e502abaf-426c-4fab-ad60-d7b5dcd730d8" />
</a>
<br>
<br>

**Autoswagger** discovers and parses **Swagger/OpenAPI** documentation and tests the endpoints it describes for access-control and data-exposure problems.

It started as an *unauthenticated* scanner — find endpoints that answer without credentials, and flag PII, secrets and large responses. This fork extends it into an **authenticated API security scanner**: give it credentials and it will also look for broken object-level authorization (IDOR), privilege escalation, injection indicators, missing rate limiting, and weak JWT handling.

> ⚠️ **Authorized use only.** Autoswagger sends requests to the target, and in authenticated/active modes it sends crafted requests. Run it **only** against systems you have explicit, written permission to test.

---

## Table of Contents
1. [Key Features](#key-features)
2. [Installation](#installation)
3. [How to Use — Step by Step](#how-to-use--step-by-step)
   - [Step 1 — Unauthenticated scan](#step-1--unauthenticated-scan)
   - [Step 2 — Authenticated scan](#step-2--authenticated-scan)
   - [Step 3 — IDOR / BOLA (two users)](#step-3--idor--bola-two-users)
   - [Step 4 — Privilege escalation (admin vs user)](#step-4--privilege-escalation-admin-vs-user)
   - [Step 5 — Injection & rate-limit checks](#step-5--injection--rate-limit-checks)
   - [Step 6 — JWT / token checks](#step-6--jwt--token-checks)
   - [Saving and piping output](#saving-and-piping-output)
4. [All Flags](#all-flags)
5. [How Detection Works](#how-detection-works)
6. [Reading the Output](#reading-the-output)
7. [Stats & Reporting](#stats--reporting)
8. [Acknowledgments](#acknowledgments)

---

## Key Features

- **Spec discovery** — from a direct spec URL, a Swagger UI page, or a brute-force list of common locations (including extensionless ones such as `/v3/api-docs`).
- **Accurate parsing** — resolves `$ref`, honours path-level and Swagger 2 parameters, uses the spec's own `example`/`default` values, and handles absolute/templated `servers` URLs.
- **Data-exposure detection** — PII via Presidio (names, emails, phones, addresses) including inside minified JSON, secrets via regex + entropy checks, and large data dumps.
- **Fewer false positives** — fingerprints a random nonexistent path and discards catch-all / soft-404 / SPA-fallback pages.
- **Authenticated scanning** — attach a token, cookie or headers, or log in interactively.
- **Authorization testing** — IDOR/BOLA (cross-user access) and privilege escalation (admin-only endpoints reachable by lower-privilege users).
- **Active testing (opt-in, GET-only)** — SQL-error and reflected-input (XSS) indicators, a bounded rate-limit probe, and JWT hygiene + signature-verification checks.
- **Readable output** — one severity-ranked table per host, with findings and redacted samples; clean JSON to stdout (`-json`) and an optional JSON report file (`-o`).

---

## Installation

Requires **Python 3.8+**.

```bash
# 1. Clone
git clone https://github.com/hassanabuya82/security.git
cd security

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download the Presidio language model (needed for PII detection)
python3 -m spacy download en_core_web_lg

# 5. Check it runs
python3 autoswagger.py -h
```

---

## How to Use — Step by Step

The tool is designed to be used in escalating stages. Start unauthenticated; only move to the next stage when you have what it needs (credentials for one user, then two, then an admin).

### Step 1 — Unauthenticated scan

Point it at a base URL or a spec URL. No credentials needed.

```bash
# Give it the API's base URL (it will discover the spec)...
python3 autoswagger.py https://api.example.com

# ...or a direct spec URL
python3 autoswagger.py https://api.example.com/openapi.json

# Add -stats for a summary, -v to see every request (and write a log file)
python3 autoswagger.py https://api.example.com -stats -v
```

What you get: a table of endpoints that answered, with a severity and the findings (PII, secrets, large responses). If some endpoints returned **401/403**, Autoswagger counts them and prints:

> *N endpoint(s) returned 401/403 (authentication required). Rerun with --login (or -H/--token) to test them as a logged-in user.*

That is your cue for Step 2.

> **Tip:** `-risk` also tests POST/PUT/PATCH/DELETE. `-all` shows 404s too. `-rate N` caps requests per second (default 30; `-rate 0` disables the limit).

### Step 2 — Authenticated scan

Supply credentials and Autoswagger attaches them to **every** request, so it sees what a logged-in user sees. Pick whichever method fits how your API authenticates:

```bash
# A bearer token
python3 autoswagger.py https://api.example.com --token "eyJhbGci..."

# An arbitrary header (repeatable) — e.g. an API key
python3 autoswagger.py https://api.example.com -H "X-API-Key: abc123"

# A cookie / session
python3 autoswagger.py https://api.example.com --cookie "session=abcd1234"

# A credentials file:  {"headers": {...}, "cookie": "...", "token": "..."}
python3 autoswagger.py https://api.example.com --auth-file creds.json

# Log in by exchanging username/password for a token
python3 autoswagger.py https://api.example.com \
  --login-url https://api.example.com/login \
  --login-data '{"username":"jane","password":"s3cret"}' \
  --token-path data.accessToken

# Or be prompted interactively (nothing typed is echoed to screen or logs)
python3 autoswagger.py https://api.example.com --login
```

`--token-path` is a dotted path into the login JSON response (e.g. `data.accessToken`, default `token`). Each result is labelled with the identity that produced it.

### Step 3 — IDOR / BOLA (two users)

**Broken object-level authorization** means one user can read another user's objects. Proving it needs **two** accounts. Autoswagger scans as user A, notes the object endpoints it could read (e.g. `/users/{id}`), then re-requests those exact URLs as user B and anonymously.

```bash
python3 autoswagger.py https://api.example.com \
  --token "$TOKEN_A" \
  --idor --token2 "$TOKEN_B"
```

- The **primary** identity (A) uses the Step 2 flags (`--token`, `-H`, `--auth-file`, `--login`).
- The **second** identity (B) uses the `2`-suffixed flags: `--token2`, `--header2`, `--cookie2`, `--auth-file2`. (With `--login`, you are prompted for both.)
- Result: **HIGH** if B gets back A's object; **CRITICAL** if an anonymous request does.
- Only `GET` is replayed (re-reading is non-destructive).

### Step 4 — Privilege escalation (admin vs user)

Scan as an **admin**, then check whether a lower-privilege user (or anonymous) can reach privileged endpoints. "Privileged" means an admin-like path (`/admin/...`, `/manage/...`, `/internal/...`) or a privileged security scope such as `admin:read`.

```bash
python3 autoswagger.py https://api.example.com \
  --token "$ADMIN_TOKEN" \
  --privesc --token2 "$USER_TOKEN"
```

- **HIGH/CRITICAL** when the same privileged data comes back to the user/anonymous.
- **MEDIUM** when the endpoint merely failed to reject them (2xx with a different body).
- With no second identity, it tests anonymous access only.

### Step 5 — Injection & rate-limit checks

Opt-in, **GET-only**, non-destructive. These send crafted requests — authorization required.

```bash
# Injection indicators on every GET parameter
python3 autoswagger.py https://api.example.com --token "$TOKEN" --injection

# Is the API rate-limited? (small bounded burst, not a load test)
python3 autoswagger.py https://api.example.com --rate-limit-check --rate-limit-burst 25
```

- **`--injection`** sends two benign markers per parameter: a single quote (looks for a *new* database error → possible SQL injection, **HIGH**) and a unique string with HTML specials (looks for it reflected unencoded in an HTML/JS response → possible XSS, **MEDIUM**). It sends **no exploit payloads**; findings are indicators to confirm by hand.
- **`--rate-limit-check`** sends a small burst (`--rate-limit-burst`, default 25, max 200) to one endpoint and reports whether the server throttled (429/503). `info` = throttling seen; `low` = none seen (rate limiting may be absent).

### Step 6 — JWT / token checks

If you authenticate with a JWT bearer token, `--jwt` adds token-specific checks.

```bash
python3 autoswagger.py https://api.example.com --token "$JWT" --jwt
```

- **Offline hygiene** (no requests): flags `alg: none` (**CRITICAL**), symmetric algorithms (**LOW**), a missing or very long `exp` (**MEDIUM/LOW**), and PII/secrets carried in the payload (**MEDIUM/HIGH**).
- **Signature verification** (one GET endpoint): re-requests it with tampered tokens — an `alg:none` variant, a stripped signature, and a corrupted signature. If any is accepted with the same response, the server is **not verifying the signature** (**CRITICAL**).

### Saving and piping output

```bash
# Human-readable tables (default)
python3 autoswagger.py https://api.example.com --token "$T"

# Clean JSON on stdout (logs go to stderr), ready for jq
python3 autoswagger.py https://api.example.com --token "$T" -json | jq '.results'

# Save the full report (results + all findings + stats) to a file
python3 autoswagger.py https://api.example.com --token "$T" -o report.json

# Only the interesting endpoints, as JSON
python3 autoswagger.py https://api.example.com --token "$T" -product
```

You can combine any of the stages in one run, e.g.:

```bash
python3 autoswagger.py https://api.example.com \
  --token "$ADMIN_TOKEN" --token2 "$USER_TOKEN" \
  --idor --privesc --injection --jwt --rate-limit-check \
  -stats -o report.json
```

---

## All Flags

| Flag | Description |
|------|-------------|
| `urls` | One or more base URLs or direct spec URLs (also read from stdin). |
| `-v, --verbose` | Verbose logging; also writes a log file under `~/.autoswagger/logs`. |
| `-risk` | Include non-GET methods (POST, PUT, PATCH, DELETE) in testing. |
| `-all` | Include all status codes in output except 401/403. |
| `-product` | Output only interesting endpoints (PII, secrets, large responses, auth-not-enforced), as JSON. |
| `-stats` | Show scan statistics. |
| `-rate N` | Total requests per second across all threads (default 30; `0` disables). |
| `-b, --brute` | Try multiple parameter-value combinations to get past validation. |
| `-json` | JSON output on stdout. |
| `-o, --output FILE` | Also write results, findings and stats as JSON to FILE. |
| **Authenticated testing** | |
| `-H, --header 'Name: value'` | Header sent with every request (repeatable). Enables authenticated scanning. |
| `--cookie STRING` | Cookie header sent with every request. |
| `--token TOKEN` | Shortcut for `-H 'Authorization: Bearer TOKEN'`. |
| `--auth-file FILE` | JSON file: `{"headers": {...}, "cookie": "...", "token": "..."}`. |
| `--login` | Prompt interactively for credentials (and a second identity with `--idor`). |
| `--login-url URL` | Log in by POSTing `--login-data` here and reading a token from the response. |
| `--login-data JSON` | JSON credentials for `--login-url`. |
| `--token-path PATH` | Dotted path to the token in the login response (default `token`). |
| **Authorization testing** | |
| `--idor` | Replay the primary identity's object reads as a second identity and anonymously; flag cross-user access. |
| `--header2 / --cookie2 / --token2 / --auth-file2` | Credentials for the second identity. |
| `--privesc` | Check whether the second identity or anonymous requests can reach privileged (admin) endpoints. |
| **Active testing (authorization required)** | |
| `--injection` | Probe GET parameters for SQL-error and reflected-input (XSS) indicators using benign markers. |
| `--rate-limit-check` | Send a small bounded burst to one endpoint and report whether it throttles. |
| `--rate-limit-burst N` | Requests in the burst (default 25, max 200). |
| `--jwt` | Analyze supplied bearer token(s) and test whether the server verifies the signature. |

---

## How Detection Works

**Spec discovery**
1. **Direct spec** — a URL ending in `.json/.yaml/.yml`, or any path that returns a valid spec (e.g. `/v3/api-docs`), is parsed directly.
2. **Swagger UI** — known UI paths are scanned; the spec URL is extracted from the HTML/JS (including `configUrl` and `swashbuckleConfig`).
3. **Brute force** — a list of common spec locations is tried only if 1 and 2 fail.

A document is accepted only if it actually looks like a spec (`swagger`/`openapi` plus a `paths` object), whatever its Content-Type.

**Endpoint testing**
- GET by default; `-risk` adds other methods.
- Parameters are filled from the spec's `example`/`default` first, then type-appropriate test values; `-b` tries more combinations.
- One shared rate limiter caps total throughput; 429/503 are retried honouring `Retry-After`.
- Before scanning, a random nonexistent path is requested to fingerprint unknown-route responses; matching catch-all/soft-404/SPA pages are discarded.

**Data exposure**
- **PII** via Presidio (names, emails, phones, addresses), parsing JSON structurally so minified bodies are covered; field-name context reduces false positives.
- **Secrets** via regex with bounded patterns and an entropy check; reported separately from PII (`secrets_data`).
- **Debug info** (stack traces, debug pages) reported as low-severity `debug_info`.
- **Large responses**: 100+ records (including `{"data":[...]}` wrappers) or >100 KB.

---

## Reading the Output

By default, results are shown as one table per host, sorted by severity:

| Severity | Meaning |
|----------|---------|
| CRITICAL | A secret in the response, or anonymous access to a protected object, or an unverified JWT signature |
| HIGH     | PII in a 2xx response, cross-user object access, or a SQL-injection indicator |
| MEDIUM   | Auth the spec requires but did not enforce, a large data dump, a reflected-input (XSS) indicator, or a privileged endpoint that failed to reject a user |
| LOW      | Stack trace / debug page, or weak-but-not-broken JWT settings |
| INFO     | Responded; nothing notable found |

The **Findings** column lists what was found, with counts and a masked sample (e.g. `PII: Email ×12 (j***@acme.io)`). Authorization, injection, rate-limit and JWT findings are shown in their own tables below the endpoint table, and included under `idor_findings`, `privesc_findings`, `injection_findings`, `rate_limit_findings` and `jwt_findings` in JSON/`-o` output.

**Interpreting:** start with CRITICAL and HIGH. Every finding is an *indicator* — confirm it by hand (curl, Postman, or Burp Suite) before reporting. INFO rows are worth a glance to decide whether those endpoints are meant to be public.

---

## Stats & Reporting

`-stats` prints a summary: hosts with a valid spec, hosts with PII, hosts with secrets, endpoints requiring auth, counts of each authorization/active finding, total requests sent and average requests/second. It is embedded in the JSON when `-json`, `-product` or `-o` is used.

---

## Acknowledgments

Autoswagger was created and is owned by **[Intruder](https://intruder.io/)**, primarily developed by Cale Anderson. This is an extended fork that adds authenticated and authorization testing. The original project and its MIT license are retained.
