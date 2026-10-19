'use strict';

function text(value) {
  return String(
    value || ''
  );
}

function lower(value) {
  return text(value)
    .toLowerCase();
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function headerValue(
  response,
  name
) {
  const headers =
    response?.headers &&
    typeof response.headers ===
      'object'
      ? response.headers
      : {};

  const wanted =
    String(name)
      .toLowerCase();

  for (
    const [
      key,
      value,
    ] of Object.entries(
      headers
    )
  ) {
    if (
      key.toLowerCase() ===
      wanted
    ) {
      return value;
    }
  }

  return null;
}

function baselineBody(context) {
  return text(
    context?.baselineResponse
      ?.body
  );
}

function signalIsNew(
  responseBody,
  baseline,
  pattern
) {
  return (
    pattern.test(
      responseBody
    ) &&
    !pattern.test(
      baseline
    )
  );
}

function result(
  verdict,
  matched,
  confidence,
  rationale
) {
  return {
    verdict,
    matched,
    confidence,
    rationale,
  };
}

function confirmed(
  rationale,
  confidence = 95
) {
  return result(
    'confirmed',
    true,
    confidence,
    rationale
  );
}

function exposure(
  rationale,
  confidence = 80
) {
  return result(
    'observed_exposure',
    true,
    confidence,
    rationale
  );
}

function inconclusive(
  rationale,
  confidence = 50
) {
  return result(
    'inconclusive',
    false,
    confidence,
    rationale
  );
}

function notReproduced(
  rationale,
  confidence = 70
) {
  return result(
    'not_reproduced',
    false,
    confidence,
    rationale
  );
}

function notApplicable(
  rationale
) {
  return result(
    'not_applicable',
    false,
    100,
    rationale
  );
}

function simulationMarker(
  attack,
  response,
  context
) {
  if (
    !context?.simulation
  ) {
    return null;
  }

  const parsed =
    parseJson(
      response?.body
    );

  if (
    parsed?.synthetic ===
      true &&
    parsed?.vulnerable ===
      true &&
    parsed?.fixture ===
      attack?.attackType
  ) {
    return confirmed(
      `The controlled ${attack.attackType} Safe Simulation fixture reproduced its expected security signal.`
    );
  }

  return null;
}


/* -------------------------------- */
/* Injection                         */
/* -------------------------------- */

function evaluateSqlInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const indicators = [
    /sql syntax/i,
    /mysql_fetch/i,
    /mysqli/i,
    /postgresql/i,
    /pg_query/i,
    /sqlite error/i,
    /sqlite3::/i,
    /ora-\d+/i,
    /odbc sql/i,
    /unclosed quotation mark/i,
    /database error/i,
  ];

  if (
    indicators.some(
      pattern =>
        signalIsNew(
          body,
          baseline,
          pattern
        )
    )
  ) {
    return confirmed(
      'The injected request introduced a database error signature that was absent from the baseline response.'
    );
  }

  return notReproduced(
    'The SQL injection probe did not produce a supported differential SQL signal.'
  );
}

function evaluateNoSqlInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /mongoerror|mongodb.*error|bson.*error|unknown operator.*\$|invalid operator.*\$/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The injected request introduced a NoSQL/database-operator error that was absent from the baseline response.'
    );
  }

  return notReproduced(
    'The NoSQL injection probe did not produce a supported differential signal.'
  );
}

function evaluateCommandInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /uid=\d+|gid=\d+|command executed|command output|current user:/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The injected request introduced output consistent with command execution.'
    );
  }

  return notReproduced(
    'The command-injection probe did not produce supported execution evidence.'
  );
}

function evaluateCodeInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /process\.env|NODE_ENV|environment variables|npm_config_/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The injected request introduced output consistent with server-side code evaluation.'
    );
  }

  return notReproduced(
    'The code-injection probe did not produce supported execution evidence.'
  );
}

function evaluateSsti(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  if (
    (
      attack?.payload ===
        '{{7*7}}' ||
      attack?.payload ===
        '${7*7}'
    ) &&
    body.includes(
      '49'
    ) &&
    !baseline.includes(
      '49'
    )
  ) {
    return confirmed(
      'The supplied template expression appears to have been evaluated.'
    );
  }

  return notReproduced(
    'The template-injection probe did not produce supported expression-evaluation evidence.'
  );
}

function evaluateLdapInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /ldap.*error|invalid ldap|bad search filter|ldap filter/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The injected request introduced an LDAP/filter-processing error that was absent from the baseline response.'
    );
  }

  return notReproduced(
    'The LDAP injection probe did not produce a supported differential signal.'
  );
}

function evaluateXpathInjection(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /xpath.*error|invalid xpath|xpath exception|xml query error/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The injected request introduced an XPath-processing error that was absent from the baseline response.'
    );
  }

  return notReproduced(
    'The XPath injection probe did not produce a supported differential signal.'
  );
}


/* -------------------------------- */
/* XSS                               */
/* -------------------------------- */

function evaluateXss(
  attack,
  response,
  context
) {
  const body =
    text(response?.body);

  if (
    context?.simulation &&
    typeof attack?.payload ===
      'string' &&
    body.includes(
      attack.payload
    )
  ) {
    return confirmed(
      'The controlled XSS fixture reflected the expected synthetic payload.'
    );
  }

  if (
    typeof attack?.payload ===
      'string' &&
    body.includes(
      attack.payload
    )
  ) {
    return inconclusive(
      'The payload was reflected in the response, but browser execution was not established.'
    );
  }

  return notReproduced(
    'The tested XSS payload was not reflected.'
  );
}


/* -------------------------------- */
/* File/path                         */
/* -------------------------------- */

function evaluatePathTraversal(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  const pattern =
    /sentinelai-canary|root:x:|daemon:x:/i;

  if (
    signalIsNew(
      body,
      baseline,
      pattern
    )
  ) {
    return confirmed(
      'The traversal request returned file-content evidence absent from the baseline.'
    );
  }

  return notReproduced(
    'The path-traversal probe did not expose supported file evidence.'
  );
}

function evaluateLfi(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline =
    baselineBody(context);

  if (
    body.includes(
      'sentinelai-canary'
    ) &&
    !baseline.includes(
      'sentinelai-canary'
    )
  ) {
    return confirmed(
      'The controlled SentinelAI file canary was returned by the application.'
    );
  }

  return notReproduced(
    'The local-file-inclusion probe did not return the SentinelAI canary.'
  );
}


/* -------------------------------- */
/* Web/server                        */
/* -------------------------------- */

function evaluateOpenRedirect(
  attack,
  response,
  context
) {
  const status =
    Number(
      response?.statusCode
    );

  const location =
    headerValue(
      response,
      'location'
    );

  if (
    status >= 300 &&
    status < 400 &&
    typeof location ===
      'string' &&
    location.includes(
      'example.invalid'
    )
  ) {
    return confirmed(
      'The application redirected to the controlled external test origin.'
    );
  }

  return notReproduced(
    'The open-redirect probe did not produce the expected controlled redirect.'
  );
}

function evaluateSsrf(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  return notApplicable(
    'SSRF Project Validation requires a SentinelAI-controlled callback canary.'
  );
}


/* -------------------------------- */
/* Authentication / authorization    */
/* -------------------------------- */

function evaluateAuthBypass(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const status =
    Number(
      response?.statusCode
    );

  const body =
    text(response?.body);

  if (
    status === 401 ||
    status === 403 ||
    /unauthorized|forbidden|authentication required|login required/i.test(
      body
    )
  ) {
    return notReproduced(
      'The protected route rejected the unauthenticated request.'
    );
  }

  if (
    status >= 200 &&
    status < 300
  ) {
    return inconclusive(
      'The protected-looking route returned successfully without credentials, but an authenticated baseline is required before authentication bypass can be confirmed.'
    );
  }

  return inconclusive(
    'The authentication probe did not provide enough evidence for a conclusion.'
  );
}


/* -------------------------------- */
/* HTTP                              */
/* -------------------------------- */

function evaluateCors(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const origin =
    headerValue(
      response,
      'access-control-allow-origin'
    );

  const credentials =
    lower(
      headerValue(
        response,
        'access-control-allow-credentials'
      )
    );

  if (
    context?.testOrigin &&
    origin ===
      context.testOrigin &&
    credentials ===
      'true'
  ) {
    return exposure(
      'The application reflected the controlled Origin while allowing credentials.'
    );
  }

  return notReproduced(
    'The supported CORS misconfiguration signal was not reproduced.'
  );
}

function evaluateSecurityHeaders(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const required = [
    'content-security-policy',
    'x-content-type-options',
    'referrer-policy',
  ];

  const missing =
    required.filter(
      name =>
        headerValue(
          response,
          name
        ) === null
    );

  if (
    missing.length > 0
  ) {
    return exposure(
      `The tested response is missing recommended security header(s): ${missing.join(', ')}.`,
      70
    );
  }

  return notReproduced(
    'The checked security headers were present.'
  );
}

function evaluateCookieSecurity(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const setCookie =
    headerValue(
      response,
      'set-cookie'
    );

  if (!setCookie) {
    return notApplicable(
      'The tested response did not set a cookie.'
    );
  }

  const cookies =
    Array.isArray(
      setCookie
    )
      ? setCookie
      : [
          setCookie,
        ];

  const issues =
    new Set();

  let https;

  try {
    https =
      new URL(
        context?.route?.url ||
        'http://sentinel.local'
      ).protocol ===
      'https:';
  } catch {
    https = false;
  }

  for (
    const cookie of cookies
  ) {
    const value =
      lower(cookie);

    if (
      !value.includes(
        'httponly'
      )
    ) {
      issues.add(
        'HttpOnly'
      );
    }

    if (
      !value.includes(
        'samesite='
      )
    ) {
      issues.add(
        'SameSite'
      );
    }

    if (
      https &&
      !value.includes(
        'secure'
      )
    ) {
      issues.add(
        'Secure'
      );
    }
  }

  if (
    issues.size > 0
  ) {
    return exposure(
      `A runtime cookie was observed without: ${Array.from(
        issues
      ).join(', ')}.`
    );
  }

  return notReproduced(
    'The observed cookie contained the checked protection attributes.'
  );
}

function evaluateUnsafeHttpMethods(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const allow =
    text(
      headerValue(
        response,
        'allow'
      )
    )
      .toUpperCase()
      .split(',')
      .map(
        value =>
          value.trim()
      )
      .filter(Boolean);

  const unsafe =
    allow.filter(
      method =>
        method ===
          'TRACE' ||
        method ===
          'CONNECT'
    );

  if (
    unsafe.length > 0
  ) {
    return exposure(
      `Potentially unsafe HTTP method(s) were advertised: ${unsafe.join(', ')}.`
    );
  }

  if (
    allow.length === 0
  ) {
    return inconclusive(
      'The server did not provide an Allow header for HTTP method analysis.'
    );
  }

  return notReproduced(
    'No supported unsafe HTTP method exposure was observed.'
  );
}


/* Exposure                          */


function evaluateSensitiveData(
  attack,
  response,
  context
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  const body =
    text(response?.body);

  const baseline = baselineBody(context);
  const { detectSensitiveData } = require('../evidence');
  const baselineExposureKeys = new Set(detectSensitiveData(baseline).map(item => `${item.dataType}:${item.maskedValue}`));
  const exposures = detectSensitiveData(body).filter(item => !baselineExposureKeys.has(`${item.dataType}:${item.maskedValue}`));
  if (exposures.length) {
    return exposure(
      `The runtime response exposed ${exposures.length} sensitive data item(s) not present in the baseline (${exposures.map(item => item.dataType).join(', ')}).`
    );
  }

  return notReproduced(
    'No supported sensitive-data exposure signal was observed.'
  );
}

function evaluateDebugExposure(
  attack,
  response
) {
  const body =
    text(response?.body);

  const patterns = [
    /traceback \(most recent call last\)/i,
    /stack trace/i,
    /uncaught exception/i,
    /werkzeug debugger/i,
    /debug mode/i,
    /\bat .+ \(.+:\d+:\d+\)/i,
  ];

  if (
    patterns.some(
      pattern =>
        pattern.test(body)
    )
  ) {
    return exposure(
      'The runtime response exposed debugging or stack-trace information.'
    );
  }

  return notReproduced(
    'No supported debug-information exposure was observed.'
  );
}

function evaluateDirectoryListing(
  attack,
  response
) {
  const body =
    text(response?.body);

  if (
    /<title>\s*index of\b/i.test(
      body
    ) ||
    /<h1>\s*index of\b/i.test(
      body
    )
  ) {
    return exposure(
      'The runtime response appears to expose a directory index.'
    );
  }

  return notReproduced(
    'No directory-index exposure was observed.'
  );
}


/* -------------------------------- */
/* Context-dependent checks          */
/* -------------------------------- */

function simulationOrNotApplicable(
  attack,
  response,
  context,
  projectMessage
) {
  const marker =
    simulationMarker(
      attack,
      response,
      context
    );

  if (marker) {
    return marker;
  }

  return notApplicable(
    projectMessage
  );
}

function evaluateIdor(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'IDOR/BOLA requires multiple authorization contexts or a trusted object-ownership baseline.'
  );
}

function evaluateJwt(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'JWT validation requires a discovered application token and authenticated baseline.'
  );
}

function evaluateCsrf(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'CSRF confirmation requires an authenticated state-changing workflow and CSRF baseline.'
  );
}

function evaluateXxe(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'XXE Project Validation requires a controlled XML/external-entity callback fixture.'
  );
}

function evaluateRequestSmuggling(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'HTTP request smuggling requires controlled front-end/back-end proxy infrastructure and is not executed by generic Project Validation.'
  );
}

function evaluateHostHeaderInjection(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Host-header injection requires a known host-dependent security workflow such as reset links, redirects, routing, or caching.'
  );
}

function evaluatePrototypePollution(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Prototype-pollution validation requires an isolated state-safe object-processing context.'
  );
}

function evaluateMassAssignment(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Mass-assignment validation requires a known object schema and authorization baseline.'
  );
}

function evaluateRaceCondition(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Race-condition validation requires a specifically approved concurrency-safe workflow.'
  );
}

function evaluateWebsocketSecurity(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'WebSocket validation requires a discovered WebSocket endpoint and dedicated transport.'
  );
}

function evaluateGraphqlSecurity(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'GraphQL validation requires a discovered GraphQL endpoint and schema/authorization context.'
  );
}

function evaluateFileUpload(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'File-upload validation requires a disposable upload endpoint and cleanup strategy.'
  );
}

function evaluateInsecureDeserialization(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Deserialization validation requires an isolated known serialization format and safe canary strategy.'
  );
}

function evaluateCachePoisoning(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Cache-poisoning validation requires a controlled cache and must not modify shared cache state during generic scans.'
  );
}

function evaluateBusinessLogic(
  attack,
  response,
  context
) {
  return simulationOrNotApplicable(
    attack,
    response,
    context,
    'Business-logic validation requires application-specific workflow and invariant definitions.'
  );
}


/* -------------------------------- */
/* Dispatcher                        */
/* -------------------------------- */

const EVALUATORS = {
  sqli:
    evaluateSqlInjection,

  nosqli:
    evaluateNoSqlInjection,

  cmdi:
    evaluateCommandInjection,

  code_injection:
    evaluateCodeInjection,

  ssti:
    evaluateSsti,

  ldap_injection:
    evaluateLdapInjection,

  xpath_injection:
    evaluateXpathInjection,

  xxe:
    evaluateXxe,

  prototype_pollution:
    evaluatePrototypePollution,

  insecure_deserialization:
    evaluateInsecureDeserialization,

  path_traversal:
    evaluatePathTraversal,

  lfi:
    evaluateLfi,

  file_upload:
    evaluateFileUpload,

  auth_bypass:
    evaluateAuthBypass,

  idor:
    evaluateIdor,

  jwt:
    evaluateJwt,

  csrf:
    evaluateCsrf,

  mass_assignment:
    evaluateMassAssignment,

  race_condition:
    evaluateRaceCondition,

  business_logic:
    evaluateBusinessLogic,

  xss:
    evaluateXss,

  open_redirect:
    evaluateOpenRedirect,

  ssrf:
    evaluateSsrf,

  host_header_injection:
    evaluateHostHeaderInjection,

  websocket_security:
    evaluateWebsocketSecurity,

  graphql_security:
    evaluateGraphqlSecurity,

  cors:
    evaluateCors,

  security_headers:
    evaluateSecurityHeaders,

  cookie_security:
    evaluateCookieSecurity,

  unsafe_http_methods:
    evaluateUnsafeHttpMethods,

  request_smuggling:
    evaluateRequestSmuggling,

  cache_poisoning:
    evaluateCachePoisoning,

  sensitive_data:
    evaluateSensitiveData,

  debug_exposure:
    evaluateDebugExposure,

  directory_listing:
    evaluateDirectoryListing,
};

function evaluateRuntimeEvidence(
  attack,
  response,
  context = {}
) {
  const evaluator =
    EVALUATORS[
      attack?.attackType
    ];

  if (!evaluator) {
    return notApplicable(
      `No runtime evaluator is registered for ${attack?.attackType || 'unknown'}.`
    );
  }

  return evaluator(
    attack,
    response,
    context
  );
}

module.exports = {
  evaluateRuntimeEvidence,
};