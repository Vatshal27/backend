'use strict';

function createAbsoluteUrl(
  value,
  targetUrl
) {
  try {
    return new URL(
      value,
      targetUrl
    ).toString();
  } catch {
    return null;
  }
}

function sameOrigin(
  value,
  targetUrl
) {
  try {
    const candidate =
      new URL(
        value,
        targetUrl
      );

    const target =
      new URL(targetUrl);

    return (
      candidate.protocol ===
        target.protocol &&
      candidate.hostname ===
        target.hostname &&
      candidate.port ===
        target.port
    );
  } catch {
    return false;
  }
}

function queryParameters(url) {
  try {
    return Array.from(
      new URL(
        url
      ).searchParams.keys()
    );
  } catch {
    return [];
  }
}

function normalizeParameters(
  parameters
) {
  return Array.from(
    new Set(
      (
        Array.isArray(parameters)
          ? parameters
          : []
      )
        .filter(Boolean)
        .map(String)
    )
  );
}

function addRoute(
  routes,
  route
) {
  if (
    !route?.url
  ) {
    return;
  }

  const parameters =
    normalizeParameters([
      ...(
        route.parameters ||
        []
      ),
      ...queryParameters(
        route.url
      ),
    ]);

  routes.push({
    method:
      String(
        route.method ||
        'GET'
      ).toUpperCase(),
    url:
      route.url,
    source:
      route.source ||
      'unknown',
    parameters,
  });
}

function discoverLinks(
  html,
  targetUrl,
  routes
) {
  const regex =
    /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>/gi;

  let match;

  while (
    (
      match =
        regex.exec(html)
    ) !== null
  ) {
    const url =
      createAbsoluteUrl(
        match[1],
        targetUrl
      );

    if (
      url &&
      sameOrigin(
        url,
        targetUrl
      )
    ) {
      addRoute(
        routes,
        {
          method:
            'GET',
          url,
          source:
            'link',
          parameters:
            [],
        }
      );
    }
  }
}

function discoverForms(
  html,
  targetUrl,
  routes
) {
  const formRegex =
    /<form\b[^>]*>[\s\S]*?<\/form>/gi;

  let formMatch;

  while (
    (
      formMatch =
        formRegex.exec(html)
    ) !== null
  ) {
    const formHtml =
      formMatch[0];

    const actionMatch =
      formHtml.match(
        /\baction=["']([^"']*)["']/i
      );

    const methodMatch =
      formHtml.match(
        /\bmethod=["']([^"']+)["']/i
      );

    const url =
      createAbsoluteUrl(
        actionMatch
          ? actionMatch[1]
          : '/',
        targetUrl
      );

    if (
      !url ||
      !sameOrigin(
        url,
        targetUrl
      )
    ) {
      continue;
    }

    const parameters =
      [];

    const inputRegex =
      /<(?:input|textarea|select)\b[^>]*\bname=["']([^"']+)["'][^>]*>/gi;

    let inputMatch;

    while (
      (
        inputMatch =
          inputRegex.exec(
            formHtml
          )
      ) !== null
    ) {
      parameters.push(
        inputMatch[1]
      );
    }

    addRoute(
      routes,
      {
        method:
          methodMatch
            ? methodMatch[1]
                .toUpperCase()
            : 'GET',
        url,
        source:
          'form',
        parameters,
      }
    );
  }
}

function discoverFetchCalls(
  html,
  targetUrl,
  routes
) {
  const regex =
    /fetch\s*\(\s*["']([^"']+)["']/gi;

  let match;

  while (
    (
      match =
        regex.exec(html)
    ) !== null
  ) {
    const url =
      createAbsoluteUrl(
        match[1],
        targetUrl
      );

    if (
      url &&
      sameOrigin(
        url,
        targetUrl
      )
    ) {
      addRoute(
        routes,
        {
          method:
            'GET',
          url,
          source:
            'javascript-fetch',
          parameters:
            [],
        }
      );
    }
  }
}

function discoverAxiosCalls(
  html,
  targetUrl,
  routes
) {
  const regex =
    /axios\.(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/gi;

  let match;

  while (
    (
      match =
        regex.exec(html)
    ) !== null
  ) {
    const url =
      createAbsoluteUrl(
        match[2],
        targetUrl
      );

    if (
      url &&
      sameOrigin(
        url,
        targetUrl
      )
    ) {
      addRoute(
        routes,
        {
          method:
            match[1]
              .toUpperCase(),
          url,
          source:
            'javascript-axios',
          parameters:
            [],
        }
      );
    }
  }
}

function deduplicateRoutes(
  routes
) {
  const unique = [];
  const seen =
    new Set();

  for (
    const route of routes
  ) {
    const key = [
      route.method,
      route.url,
      (
        route.parameters ||
        []
      )
        .slice()
        .sort()
        .join(','),
    ].join('|');

    if (
      seen.has(key)
    ) {
      continue;
    }

    seen.add(key);
    unique.push(route);
  }

  return unique;
}

function discoverRoutes(
  body,
  targetUrl,
  options = {}
) {
  const {
    maxRoutes = 100,
  } = options;

  const html =
    typeof body === 'string'
      ? body
      : '';

  const routes = [];

  discoverLinks(
    html,
    targetUrl,
    routes
  );

  discoverForms(
    html,
    targetUrl,
    routes
  );

  discoverFetchCalls(
    html,
    targetUrl,
    routes
  );

  discoverAxiosCalls(
    html,
    targetUrl,
    routes
  );

  addRoute(
    routes,
    {
      method:
        'GET',
      url:
        targetUrl,
      source:
        'root',
      parameters:
        [],
    }
  );

  return deduplicateRoutes(
    routes
  ).slice(
    0,
    maxRoutes
  );
}

module.exports = {
  createAbsoluteUrl,
  sameOrigin,
  discoverRoutes,
  deduplicateRoutes,
};