# SentinelAI Security Report

**Generated:** 14 October 2026 at 03:56:44
**Expires:** 15 October 2026 at 03:56:44
**Time Zone:** Asia/Kolkata
**Target:** http://localhost:5173
**Report Type:** Compiled Security Report

> Local SentinelAI report files are retained for 24 hours and are then automatically removed.

---

## Executive Summary

SentinelAI did not confirm a vulnerability or sensitive-data exposure in the checks performed.

### Project Security Results

| Result | Count |
|---|---:|
| Confirmed vulnerabilities | 0 |
| Observed exposures | 0 |
| Inconclusive | 1 |
| Not reproduced | 4 |
| Runtime tests | 35 |
| Failed tests | 0 |
| Runtime duration | 479 ms |

### SentinelAI Runtime Engine Self-Test

| Result | Count |
|---|---:|
| Controlled fixtures | 44 |
| Successfully detected | 42 |
| Inconclusive | 0 |
| Failed tests | 0 |
| Detection coverage | 42 / 44 |

> Safe Simulation validates SentinelAI against controlled synthetic vulnerability fixtures. These detections are scanner self-test results and are not project vulnerabilities.

## Static Analysis Findings

No static analysis findings were reported.

## AI Analysis Findings

No AI analysis findings were reported.

## Sensitive Data Exposure

No sensitive-data exposure was detected in the runtime responses checked during this scan.

## Project Runtime Validation

| Check | Verdict | Target | HTTP |
|---|---|---|---:|
| cors | Not Reproduced | http://localhost:5173/ | 200 |
| security_headers | Inconclusive | http://localhost:5173/ | 200 |
| cookie_security | not_applicable | http://localhost:5173/ | 200 |
| unsafe_http_methods | Inconclusive | http://localhost:5173/ | 204 |
| sensitive_data | Not Reproduced | http://localhost:5173/ | 200 |
| debug_exposure | Not Reproduced | http://localhost:5173/ | 200 |
| directory_listing | Not Reproduced | http://localhost:5173/ | 200 |
| SQL Injection | not_applicable |  |  |
| nosqli | not_applicable |  |  |
| Command Injection | not_applicable |  |  |
| Code Injection | not_applicable |  |  |
| ssti | not_applicable |  |  |
| ldap_injection | not_applicable |  |  |
| xpath_injection | not_applicable |  |  |
| xxe | not_applicable |  |  |
| prototype_pollution | not_applicable |  |  |
| insecure_deserialization | not_applicable |  |  |
| Path Traversal | not_applicable |  |  |
| lfi | not_applicable |  |  |
| file_upload | not_applicable |  |  |
| Authentication Bypass | not_applicable |  |  |
| idor | not_applicable |  |  |
| jwt | not_applicable |  |  |
| csrf | not_applicable |  |  |
| mass_assignment | not_applicable |  |  |
| race_condition | not_applicable |  |  |
| business_logic | not_applicable |  |  |
| Cross-Site Scripting (XSS) | not_applicable |  |  |
| open_redirect | not_applicable |  |  |
| ssrf | not_applicable |  |  |
| host_header_injection | not_applicable |  |  |
| websocket_security | not_applicable |  |  |
| graphql_security | not_applicable |  |  |
| request_smuggling | not_applicable |  |  |
| cache_poisoning | not_applicable |  |  |

### Probe 1: cors

- **Verdict:** Not Reproduced
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

**Assessment**

The supported CORS misconfiguration signal was not reproduced.

### Probe 2: security_headers

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

### Probe 3: cookie_security

- **Verdict:** not_applicable
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

**Assessment**

The tested response did not set a cookie.

### Probe 4: unsafe_http_methods

- **Verdict:** Inconclusive
- **Target:** `http://localhost:5173/`
- **Request:** `OPTIONS http://localhost:5173/`
- **HTTP Status:** 204
- **Content Type:** empty
- **Response Size:** 0 bytes

**Assessment**

The server did not provide an Allow header for HTTP method analysis.

### Probe 5: sensitive_data

- **Verdict:** Not Reproduced
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

**Assessment**

No supported sensitive-data exposure signal was observed.

### Probe 6: debug_exposure

- **Verdict:** Not Reproduced
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

**Assessment**

No supported debug-information exposure was observed.

### Probe 7: directory_listing

- **Verdict:** Not Reproduced
- **Target:** `http://localhost:5173/`
- **Request:** `GET http://localhost:5173/`
- **HTTP Status:** 200
- **Content Type:** text/html
- **Response Size:** 658 bytes

**Assessment**

No directory-index exposure was observed.

### Probe 8: SQL Injection

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 9: nosqli

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 10: Command Injection

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 11: Code Injection

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 12: ssti

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 13: ldap_injection

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 14: xpath_injection

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 15: xxe

- **Verdict:** not_applicable

**Assessment**

XML External Entity requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 16: prototype_pollution

- **Verdict:** not_applicable

**Assessment**

Prototype Pollution requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 17: insecure_deserialization

- **Verdict:** not_applicable

**Assessment**

Insecure Deserialization requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 18: Path Traversal

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 19: lfi

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 20: file_upload

- **Verdict:** not_applicable

**Assessment**

Unsafe File Upload requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 21: Authentication Bypass

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 22: idor

- **Verdict:** not_applicable

**Assessment**

IDOR / BOLA requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 23: jwt

- **Verdict:** not_applicable

**Assessment**

JWT Security requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 24: csrf

- **Verdict:** not_applicable

**Assessment**

Cross-Site Request Forgery requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 25: mass_assignment

- **Verdict:** not_applicable

**Assessment**

Mass Assignment requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 26: race_condition

- **Verdict:** not_applicable

**Assessment**

Race Condition requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 27: business_logic

- **Verdict:** not_applicable

**Assessment**

Business Logic Flaw requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 28: Cross-Site Scripting (XSS)

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 29: open_redirect

- **Verdict:** not_applicable

**Assessment**

No discovered route matched the applicability requirements for this runtime check.

### Probe 30: ssrf

- **Verdict:** not_applicable

**Assessment**

Server-Side Request Forgery requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 31: host_header_injection

- **Verdict:** not_applicable

**Assessment**

Host Header Injection requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 32: websocket_security

- **Verdict:** not_applicable

**Assessment**

WebSocket Security requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 33: graphql_security

- **Verdict:** not_applicable

**Assessment**

GraphQL Security requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 34: request_smuggling

- **Verdict:** not_applicable

**Assessment**

HTTP Request Smuggling requires additional trusted application context before SentinelAI can test it safely against a project runtime.

### Probe 35: cache_poisoning

- **Verdict:** not_applicable

**Assessment**

Web Cache Poisoning requires additional trusted application context before SentinelAI can test it safely against a project runtime.

## Scanner Self-Test Details

| Controlled Check | Result | HTTP |
|---|---|---:|
| SQL Injection | Detected | 200 |
| SQL Injection | Detected | 200 |
| SQL Injection | Detected | 200 |
| nosqli | Detected | 200 |
| nosqli | Detected | 200 |
| Command Injection | Detected | 200 |
| Command Injection | Detected | 200 |
| Command Injection | Detected | 200 |
| Code Injection | Detected | 200 |
| ssti | Detected | 200 |
| ssti | Detected | 200 |
| ldap_injection | Detected | 200 |
| ldap_injection | Detected | 200 |
| xpath_injection | Detected | 200 |
| xpath_injection | Detected | 200 |
| xxe | Detected | 200 |
| prototype_pollution | Detected | 200 |
| insecure_deserialization | Detected | 200 |
| Path Traversal | Detected | 200 |
| lfi | Detected | 200 |
| file_upload | Detected | 200 |
| Authentication Bypass | Detected | 200 |
| idor | Detected | 200 |
| jwt | Detected | 200 |
| csrf | Detected | 200 |
| mass_assignment | Detected | 200 |
| race_condition | Detected | 200 |
| business_logic | Detected | 200 |
| Cross-Site Scripting (XSS) | Detected | 200 |
| Cross-Site Scripting (XSS) | Detected | 200 |
| open_redirect | Detected | 302 |
| ssrf | Detected | 200 |
| host_header_injection | Detected | 200 |
| websocket_security | Detected | 200 |
| graphql_security | Detected | 200 |
| cors | Detected | 200 |
| security_headers | Detected | 200 |
| cookie_security | Detected | 200 |
| unsafe_http_methods | Detected | 200 |
| request_smuggling | Detected | 200 |
| cache_poisoning | Detected | 200 |
| sensitive_data | Detected | 200 |
| debug_exposure | Inconclusive | 500 |
| directory_listing | Inconclusive | 200 |

These controlled results verify that the runtime scanner can detect its known synthetic fixtures. They do not represent vulnerabilities in the project target.

## Project Validation Execution

- **Step 1:** Initializing controlled validation against the local project runtime. — started
- **Step 2:** Docker 29.8.2 is available. — success
- **Step 3:** Required sandbox images are available. — success
- **Step 4:** Controlled bridge network created with local host access. — success
- **Step 5:** Local project runtime http://localhost:5173 is available through the temporary SentinelAI validation proxy. — success
- **Step 6:** 35 runtime validation plan(s) created. — success
- **Step 7:** 35 validation attack(s) completed. — success
- **Step 8:** Validation evidence normalized and verdicts generated. — success

## Safe Simulation Execution

- **Step 1:** Initializing isolated Safe Simulation environment. — started
- **Step 2:** Docker 29.8.2 is available. — success
- **Step 3:** Required sandbox images are available. — success
- **Step 4:** Isolated internal Docker network created for Safe Simulation. — success
- **Step 5:** Synthetic Safe Simulation target started at http://target:8080. — running
- **Step 6:** Synthetic Safe Simulation target is healthy inside the isolated sandbox at http://target:8080. — success
- **Step 7:** 35 runtime validation plan(s) created. — success
- **Step 8:** 44 validation attack(s) completed. — success
- **Step 9:** Validation evidence normalized and verdicts generated. — success

---

*Generated automatically by SentinelAI.*
