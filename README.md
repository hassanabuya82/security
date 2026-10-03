# [Autoswagger](https://www.intruder.io/research/broken-authorization-apis-autoswagger) by [Intruder](https://intruder.io/)
<a href="https://intruder.io/">
  <img width="966" alt="output" src="https://github.com/user-attachments/assets/e502abaf-426c-4fab-ad60-d7b5dcd730d8" />
</a>
<br>  
<br>  

**[Autoswagger](https://www.intruder.io/research/broken-authorization-apis-autoswagger)** is a command-line tool designed to discover, parse, and test for unauthenticated endpoints using **Swagger/OpenAPI** documentation. It helps identify potential security issues in unprotected endpoints of APIs, such as PII leaks and common secret exposures.

**Please note that this initial release of Autoswagger is by no means complete, and there are some types of specification which the tool does not currently handle. Please feel free to use it as you wish, and extend its detection capabilities or add detection regexes to cover your specific use-case!**

---

## Table of Contents
1. [Introduction](#introduction)
2. [Key Features](#key-features)
3. [Installation & Usage](#installation--usage)
4. [Discovery Phases](#discovery-phases)
5. [Endpoint Testing](#endpoint-testing)
6. [PII Detection](#pii-detection)
7. [Output Examples](#output)
8. [Stats & Reporting](#stats--reporting)
9. [Acknowledgments](#acknowledgments)

---

## Introduction

Autoswagger automates the process of finding **OpenAPI/Swagger** specifications, extracting API endpoints, and systematically testing them for **PII** exposure, **secrets**, and large or interesting responses. It leverages **Presidio** for PII recognition and **regex** for sensitive key/token detection.

By default it scans **unauthenticated**. When endpoints return 401/403, it reports how many require auth and suggests rerunning with credentials. Supplying credentials (`-H`, `--token`, `--auth-file`, or interactive `--login`) scans the API **as a logged-in user**, which is the foundation for the authorization testing on the roadmap (IDOR, privilege escalation).

> **Authorized use only.** Run Autoswagger only against systems you have explicit written permission to test, especially in authenticated mode.

---

## Key Features

- **Multiple Discovery Phases**  
  Discovers OpenAPI specs in three ways:
  1. **Direct Spec**: If a full URL with a path ending in `.json`, `.yaml`, or `.yml` is provided, parse that file directly.  
  2. **Swagger UI**: Parse known paths of Swagger UI (e.g. `/swagger-ui.html`), and extract spec from HTML or JavaScript.  
  3. **Direct Spec by Bruteforce**: Attempt discovery using common OpenAPI schema locations (`/swagger.json`, `/openapi.json`, etc.). Only attempt this if 1. and 2. did not yield a result.

- **Parallel Endpoint Testing**  
  Multi-threaded concurrent testing of many endpoints, respecting a configurable rate limit (`-rate`).

- **Brute-Force of Parameter Values**  
  If `-b` or `--brute` is used, try using various data types with a few example values in an attempt to bypass parameter-specific validations.

- **Presidio PII Detection**  
  Check output for phone numbers, emails, addresses, and names (with context validation to reduce false positives). Also parse CSV rows and naive “key: value” lines.

- **Secrets Detection**  
  Leverages a set of regex patterns to detect tokens, keys, and debugging artifacts (like environment variables).

- **Command Line or JSON Output**  
  In default mode, displays results in a table. With `-json`, output a JSON structure. `-product` mode filters output to only show those that contain PII, secrets, or large responses.


---

## Installation & Usage

1. **Clone** or **download** the repository containing Autoswagger.
   ```bash
   git clone git@github.com:intruder-io/autoswagger.git
   ```


2. **Install dependencies** (e.g., using Python 3.7+):
   ```bash
   pip install -r requirements.txt
   ```

   (It's recommended to use a virtual environment for this: `python3 -m venv venv;source venv/bin/activate`)

3. **Check installation, show help:**
  ```bash
  python3 autoswagger.py -h
  ```



## Flags 

| Flag                 | Description                                                                                                 |
|----------------------|-------------------------------------------------------------------------------------------------------------|
| `urls`               | List of base URLs or direct spec URLs.                                                                       |
| `-v, --verbose`      | Enables verbose logging. Creates a log file under `~/.autoswagger/logs`.                                     |
| `-risk`              | Includes non-GET methods (POST, PUT, PATCH, DELETE) in testing.                                              |
| `-all`               | Includes 200 and 404 endpoints in output (excludes 401/403).                                                 |
| `-product`           | Outputs only endpoints with PII or large responses, in JSON format.                                          |
| `-stats`             | Displays scan statistics (e.g. requests, RPS, hosts with PII).                                               |
| `-rate <N>`          | Throttles requests to N requests per second. Default is 30. Use 0 to disable rate limiting.                  |
| `-b, --brute`        | Enables brute-forcing of parameter values (multiple test combos).                                            |
| `-json`              | Outputs results in JSON format instead of a Rich table in default mode.                                      |
| `-o, --output FILE`  | Also writes results and stats as JSON to FILE.                                                               |
| `-H, --header`       | Header sent with every request (repeatable), e.g. `-H 'Authorization: Bearer ...'`. Enables authenticated scanning. |
| `--cookie STRING`    | Cookie header sent with every request.                                                                      |
| `--token TOKEN`      | Shortcut for `-H 'Authorization: Bearer TOKEN'`.                                                             |
| `--auth-file FILE`   | JSON file: `{"headers": {...}, "cookie": "...", "token": "..."}`.                                            |
| `--login`            | Prompt interactively for credentials before scanning.                                                       |
| `--login-url URL`    | Log in by POSTing `--login-data` (JSON) here and reading a token from the response.                          |
| `--login-data JSON`  | JSON credentials for `--login-url`.                                                                          |
| `--token-path PATH`  | Dotted path to the token in the login response (default: `token`).                                           |
| `--idor`             | After scanning as the primary identity, replay object reads as a second identity and anonymously; flag cross-user access (BOLA/IDOR). |
| `--header2 / --cookie2 / --token2 / --auth-file2` | Credentials for the second identity used by `--idor`.                            |


## Help

```


      /   | __  __/ /_____  ______      ______ _____ _____ ____  _____
     / /| |/ / / / __/ __ \/ ___/ | /| / / __ `/ __ `/ __ `/ _ \/ ___/
    / ___ / /_/ / /_/ /_/ (__  )| |/ |/ / /_/ / /_/ / /_/ /  __/ /
    /_/  |_\__,_/\__/\____/____/ |__/|__/_\__,_/\__, /\__, /\___/_/
                                              /____//____/
                              https://intruder.io
                          Find unauthenticated endpoints

usage: autoswagger.py [-h] [-v] [-risk] [-all] [-product] [-stats] [-rate RATE] [-b] [-json] [-o FILE] [urls ...]

Autoswagger: Detect unauthenticated access control issues via Swagger/OpenAPI documentation.

positional arguments:
  urls           Base URL(s) or spec URL(s) of the target API(s)

options:
  -h, --help     show this help message and exit
  -v, --verbose  Enable verbose output
  -risk          Include non-GET requests in testing
  -all           Include all HTTP status codes in the results, excluding 401 and 403
  -product       Output all endpoints in JSON, flagging those that contain PII or have large responses.
  -stats         Display scan statistics. Included in JSON if -product or -json is used.
  -rate RATE     Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.
  -b, --brute    Enable exhaustive testing of parameter values.
  -json          Output results in JSON format in default mode.
  -o, --output FILE  Also write results and stats as JSON to FILE.

Example usage:
  python autoswagger.py https://api.example.com -v

```
## Discovery Phases

1. **Direct Spec**  
   If a provided URL ends with `.json/.yaml/.yml`, Autoswagger **directly** attempts to parse the OpenAPI schema.

2. **Swagger-UI Detection**  
   - Tries known UI paths (e.g., `/swagger-ui.html`).
   - If found, parses the HTML or local JavaScript files for a `swagger.json` or `openapi.json`.
   - Can detect embedded configs like `window.swashbuckleConfig`.

3. **Direct Spec by Bruteforce**  
   - If no spec is found so far, Autoswagger attempts a list of default endpoints like `/swagger.json`, `/openapi.json`, etc.
   - Stops when a valid spec is discovered or none are found.

---

## Endpoint Testing

1. **Collect Endpoints**  
   After loading a spec, Autoswagger extracts each path and method under the `paths` key.

2. **HTTP Methods**  
   - By default, tests `GET` only.  
   - Use `-risk` to include other methods (`POST`, `PUT`, `PATCH`, `DELETE`).

3. **Parameter Values**  
   - Fill path/query parameters with defaults or values to enumerate.  
   - Optionally builds request bodies from the spec’s `requestBody` (OpenAPI 3) or body parameters (Swagger 2).

4. **Rate Limiting & Concurrency**  
   - `-rate` caps the total requests per second across all threads.  
   - 429/503 responses are retried after `Retry-After` (backing off every thread); 502/504 are retried for GET only.  
   - Each endpoint is tested in a dedicated job.

5. **Response Analysis**  
   - Decodes responses, checks for PII, secrets, and large content.  
   - Logs relevant findings.

---

## PII Detection

1. **Presidio-Based Analysis**  
   - Searches for phone numbers, emails, addresses, names.  
   - Context-based scanning (e.g., CSV headers, key-value lines).

2. **Secrets & Debug Info**  
   - TruffleHog-like regex checks for API keys, tokens, environment variables.  
   - Secrets are reported separately from PII (`secrets_data`); stack traces and debug pages are reported as low-severity `debug_info`.

3. **Large Response Check**  
   - Flags responses with 100+ JSON elements or large XML structures as “interesting.”  
   - Also checks raw size threshold (e.g., >100k bytes).

---

## Output

By default, output is shown as one table per host, sorted by severity:

| Severity | Meaning |
|----------|---------|
| CRITICAL | A secret (API key, token, private key) is in the response, at any status code |
| HIGH     | PII in a 2xx response |
| MEDIUM   | A 2xx from an endpoint the spec says requires auth, or a large data dump (100+ records or >100 KB) |
| LOW      | Stack trace or debug page |
| INFO     | Responded, nothing notable found |

The **Findings** column lists what was found, with counts and a masked sample (e.g. `PII: Email ×12 (j***@acme.io)`).

Before testing, Autoswagger requests a random nonexistent path to learn what the server returns for unknown routes, and discards responses that match it (catch-all pages and SPA fallbacks that return 200 for every path).

- `-json` produces JSON objects, grouping results by endpoint. Logs go to stderr, so `-json` output can be piped straight into tools like `jq`.
- `-product` filters down to only “interesting” endpoints (PII, secrets, large responses and auth not enforced).
- `-o FILE` additionally saves results and stats as JSON.

---

## Interpreting Results

Start with CRITICAL and HIGH rows: these are responses that contained secrets or PII without authentication. "Auth not enforced" findings are endpoints the spec itself says need credentials, but which answered an unauthenticated request with a 2xx. These are strong candidates for broken access control. All findings should be manually checked to confirm. You may also wish to look at INFO rows and determine whether it's intended for these endpoints to be public or not.

Simple GET endpoints can be triaged using command line tools like curl, but we would recommend using your usual API testing suite (tools such as Postman or Burp Suite) to replay requests and read responses to confirm whether an exposure is present.

---

## Authorization testing (IDOR / BOLA)

With `--idor` and two identities, Autoswagger looks for **broken object-level authorization** — one user reading another user's objects:

1. It scans as the **primary** identity (`-H`/`--token`/`--login`) and records the object endpoints (e.g. `/users/{id}`) it could read.
2. It re-requests each of those exact URLs as the **second** identity (`--token2`/`--auth-file2`/`--header2`) and anonymously.
3. If the second identity or an anonymous request gets back the **same object**, that is reported as a finding: `HIGH` for cross-user access, `CRITICAL` for anonymous access.

```bash
python3 autoswagger.py https://api.example.com --token "$TOKEN_A" --idor --token2 "$TOKEN_B"
```

Only `GET` is replayed (re-reading is non-destructive). This needs real credentials for two accounts; run it only against systems you are authorized to test.

---

## Stats & Reporting

- `-stats` appends or prints overall statistics, such as:
  - Hosts with valid specs
  - Hosts with PII, hosts with secrets
  - Total requests sent, average RPS
  - Percentage of endpoints responding with 2xx or 4xx
  - Shown in either a Rich table in default mode or embedded in JSON if `-json` or `-product` is used.

---

## Acknowledgments

Autoswagger is maintained and owned by **[Intruder](https://intruder.io/)**. It was primarily developed by Cale Anderson

