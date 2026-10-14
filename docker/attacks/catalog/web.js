'use strict';

module.exports = [
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    family: 'client',
    enabled: true,
    activeProbe: true,

    aliases: [
      'xss',
      'cross site scripting',
      'cross-site scripting',
      'reflected xss',
      'stored xss',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'query',
      'body',
    ],

    routeHints: [
      'search',
      'greet',
      'comment',
      'message',
      'profile',
      'name',
    ],

    parameterHints: [
      'name',
      'q',
      'query',
      'search',
      'message',
      'comment',
      'text',
      'content',
    ],

    payloads: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
    ],

    validator: 'xss',
  },

  {
    id: 'open_redirect',
    name: 'Open Redirect',
    family: 'client',
    enabled: true,
    activeProbe: true,

    aliases: [
      'open redirect',
      'open-redirect',
      'unvalidated redirect',
      'redirect injection',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [
      'query',
    ],

    routeHints: [
      'redirect',
      'login',
      'logout',
      'continue',
      'return',
    ],

    parameterHints: [
      'next',
      'url',
      'redirect',
      'redirectUrl',
      'return',
      'returnUrl',
      'continue',
      'destination',
    ],

    payloads: [
      'https://example.invalid',
    ],

    validator: 'open_redirect',
  },

  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    family: 'server-side',
    enabled: true,

    /*
     * Project mode requires a SentinelAI-owned callback canary.
     */
    activeProbe: false,

    aliases: [
      'ssrf',
      'server side request forgery',
      'server-side request forgery',
      'backend request forgery',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'query',
      'body',
    ],

    routeHints: [
      'fetch',
      'proxy',
      'url',
      'webhook',
      'preview',
      'import',
    ],

    parameterHints: [
      'url',
      'uri',
      'endpoint',
      'target',
      'webhook',
      'callback',
      'link',
    ],

    payloads: [],

    validator: 'ssrf',
  },

  {
    id: 'host_header_injection',
    name: 'Host Header Injection',
    family: 'client',
    enabled: true,
    activeProbe: false,

    aliases: [
      'host header injection',
      'host-header injection',
      'host header poisoning',
      'x-forwarded-host injection',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [
      'header',
    ],

    routeHints: [
      'reset',
      'redirect',
      'login',
      'account',
    ],

    parameterHints: [
      'host',
      'x-forwarded-host',
      'forwarded',
    ],

    payloads: [],

    validator: 'host_header_injection',
  },

  {
    id: 'websocket_security',
    name: 'WebSocket Security',
    family: 'client',
    enabled: true,
    activeProbe: false,

    aliases: [
      'websocket security',
      'websocket vulnerability',
      'websocket authentication',
      'cross site websocket hijacking',
      'cross-site websocket hijacking',
      'cswsh',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [
      'header',
      'message',
    ],

    routeHints: [
      'ws',
      'websocket',
      'socket',
      'realtime',
    ],

    parameterHints: [],

    payloads: [],

    validator: 'websocket_security',
  },

  {
    id: 'graphql_security',
    name: 'GraphQL Security',
    family: 'server-side',
    enabled: true,
    activeProbe: false,

    aliases: [
      'graphql security',
      'graphql introspection',
      'graphql abuse',
      'graphql authorization',
      'graphql vulnerability',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'query',
      'body',
      'json',
    ],

    routeHints: [
      'graphql',
      'graphiql',
    ],

    parameterHints: [
      'query',
      'operationName',
      'variables',
    ],

    payloads: [],

    validator: 'graphql_security',
  },
];