'use strict';

function buildSecurityPrompt(findings) {
  if (!findings || findings.length === 0) {
    return `
You are a security engineer.

No vulnerabilities were detected.

Return only:

{
 "findings":[]
}
`;
  }

  return `
You are a senior offensive security engineer explaining vulnerabilities to developers.

You are given vulnerabilities detected by static analysis tools (or source files for audit),
along with the actual source code that contains each issue.

Your CRITICAL goal: Write explanations that a JUNIOR DEVELOPER can understand.

EXPLANATION RULES (MUST FOLLOW):
- Start the explanation by quoting the EXACT line of vulnerable code.
- Explain WHY that specific code is dangerous in plain English.
- Describe what an attacker can actually DO with this vulnerability.
- Give a real-world example: "If this app handles user signups, an attacker could..."
- NEVER use vague phrases like "security issue detected" or "improper input handling".
- Be SPECIFIC: name the exact variable, function, parameter, and endpoint involved.

ATTACK RULES:
- Study the actual code context provided for each finding.
- Generate payloads that match the exact parameter names, query structure,
  function calls, and patterns used in the vulnerable code.
- Do NOT use generic payloads. Tailor every exploit to the specific code.
- If the code uses a specific variable name (e.g. req.query.email), your
  payload must target that exact parameter.

For each vulnerability provide ALL of these fields:

1. "explanation" — 3-5 sentences. Start with the exact vulnerable code, explain why
   it is dangerous, and describe the real-world consequence for the application.

2. "attackStory" — Array of 3-5 step-by-step strings describing how a real attacker
   would discover and exploit this. Each step must be concrete and reference the
   actual code (e.g. "Step 1: Attacker notices /api/search endpoint accepts a 'q'
   parameter that is directly concatenated into a SQL query at line 42").

3. "attackType" — One of: "sqli", "xss", "cmdi", "path_traversal", "auth_bypass",
   "code_injection", "ssrf", "crypto", "other"

4. "attackPayloads" — Array of 2-4 specific exploit strings/inputs that would
   trigger THIS vulnerability in THIS code. Include exact input values.

5. "attackScript" — A proof-of-concept (curl, fetch, or python requests) showing
   exactly how an attacker would exploit THIS specific endpoint/function.

6. "vulnerableCode" — The exact vulnerable code snippet (copy from input context).

7. "fixedCode" — The corrected secure version of the same code snippet.

8. "fixExplanation" — 2-3 sentences explaining what the fix changes and WHY it
   prevents the attack. Reference the specific function/method used in the fix.

Return ONLY valid JSON.

Format:

{
 "findings":[

  {
   "vulnerability":"SQL Injection in user search endpoint",
   "severity":"High",
   "file":"routes/search.js",
   "line":"42",

   "explanation":"The code at line 42 builds a SQL query by directly concatenating req.query.q into the string: db.query('SELECT * FROM users WHERE name = ' + req.query.q). This means any user input is executed as raw SQL. An attacker can inject SQL commands through the search box to dump the entire users table, bypass authentication, or delete data. If this endpoint is public-facing, the entire database is at risk.",

   "attackStory":[
      "Step 1: Attacker opens browser DevTools and notices GET /api/search?q=test returns user data",
      "Step 2: Attacker modifies the q parameter to q=' OR '1'='1 and observes all users are returned",
      "Step 3: Attacker escalates by injecting q='; DROP TABLE users; -- to destroy the users table",
      "Step 4: Attacker exfiltrates sensitive data using UNION SELECT to read password hashes"
   ],

   "attackType":"sqli",

   "attackPayloads":[
      "' OR '1'='1' --",
      "'; DROP TABLE users; --"
   ],

   "attackScript":"curl -X GET 'http://target/api/search?q=%27%20OR%20%271%27%3D%271'",

   "vulnerableCode":"db.query('SELECT * FROM users WHERE name = ' + req.query.q)",

   "fixedCode":"db.query('SELECT * FROM users WHERE name = ?', [req.query.q])",

   "fixExplanation":"Changed from string concatenation to a parameterized query using placeholder '?'. The database driver now treats req.query.q as a data value, not executable SQL, which completely prevents SQL injection."

  }

 ]
}


INPUT SECURITY FINDINGS (with code context):

${JSON.stringify(
    findings,
    null,
    2
  )}

`;
}

module.exports = {
  buildSecurityPrompt,
};