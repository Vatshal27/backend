# SentinelAI Security Report

**Generated:** 09 October 2026 at 02:26:28
**Expires:** 10 October 2026 at 02:26:28
**Time Zone:** Asia/Calcutta
**Target:** http://localhost:5173
**Mode:** Project Validation

> Local SentinelAI report files are retained for 24 hours and are then automatically removed.

---

## Executive Summary

SentinelAI did not confirm a vulnerability or sensitive-data exposure in the checks performed.

| Result | Count |
|---|---:|
| Confirmed vulnerabilities | 0 |
| Observed exposures | 0 |
| Inconclusive | 6 |
| Not reproduced | 0 |
| Runtime tests | 6 |
| Failed tests | 0 |
| Duration | 496 ms |

## Static Analysis Findings

No static analysis findings were reported.

## AI Analysis Findings

No ai analysis findings were reported.

## Sensitive Data Exposure

No sensitive-data exposure was detected in the runtime responses checked during this scan.

## Runtime Validation

| Check | Verdict | Target | HTTP |
|---|---|---|---:|
| SQL Injection | Inconclusive | http://localhost:5173/ | 200 |
| Cross-Site Scripting (XSS) | Inconclusive | http://localhost:5173/ | 200 |
| Command Injection | Inconclusive | http://localhost:5173/ | 200 |
| Path Traversal | Inconclusive | http://localhost:5173/ | 200 |
| Authentication Bypass | Inconclusive | http://localhost:5173/ | 200 |
| Code Injection | Inconclusive | http://localhost:5173/ | 200 |

### Probe 1: SQL Injection

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/?q=%27+OR+%271%27%3D%271`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

### Probe 2: Cross-Site Scripting (XSS)

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

### Probe 3: Command Injection

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/?host=localhost%3Bwhoami`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

### Probe 4: Path Traversal

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/?file=..%2Fsecret.txt`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

### Probe 5: Authentication Bypass

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The tested route returned successfully, but it was not identified as a protected resource, so authentication bypass cannot be confirmed.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

### Probe 6: Code Injection

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/?code=process.env`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 612 bytes

**Assessment**

The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.

<details>
<summary>Redacted response preview</summary>

```text
<!doctype html>
<html lang="en">
  <head>
    <script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>

    <script type="module" src="/@vite/client"></script>

    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>cyberaid</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>

```

</details>

## Validation Execution

- **Step 1:** Initializing controlled validation against the local project runtime. — started
- **Step 2:** Docker 29.8.2 is available. — success
- **Step 3:** Required sandbox images are available. — success
- **Step 4:** Controlled bridge network created with local host access. — success
- **Step 5:** Local project runtime http://localhost:5173 is available through the temporary SentinelAI validation proxy. — success
- **Step 6:** 6 runtime validation plan(s) created. — success
- **Step 7:** 6 validation attack(s) completed. — success
- **Step 8:** Validation evidence normalized and verdicts generated. — success

---

*Generated automatically by SentinelAI.*
