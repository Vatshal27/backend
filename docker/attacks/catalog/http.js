'use strict';

module.exports = [
  {
    id: 'cors',
    name: 'CORS Misconfiguration',
    family: 'http-configuration',
    enabled: true,
    activeProbe: true,

    aliases: [
      'cors',
      'cors misconfiguration',
      'cross origin resource sharing',
      'cross-origin resource sharing',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [
      'header',
    ],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'cors',
  },

  {
    id: 'security_headers',
    name: 'Security Headers',
    family: 'http-configuration',
    enabled: true,
    activeProbe: false,

    aliases: [
      'security headers',
      'missing security headers',
      'http security headers',
      'content security policy',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'security_headers',
  },

  {
    id: 'cookie_security',
    name: 'Cookie Security',
    family: 'http-configuration',
    enabled: true,
    activeProbe: false,

    aliases: [
      'cookie security',
      'insecure cookie',
      'cookie flags',
      'httponly',
      'samesite',
      'secure cookie',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'cookie',
      'header',
    ],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'cookie_security',
  },

  {
    id: 'unsafe_http_methods',
    name: 'Unsafe HTTP Methods',
    family: 'http-configuration',
    enabled: true,
    activeProbe: false,

    aliases: [
      'unsafe http methods',
      'dangerous http methods',
      'http methods',
      'trace method',
      'connect method',
    ],

    methods: [
      'OPTIONS',
    ],

    inputLocations: [],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'unsafe_http_methods',
  },

  {
    id: 'request_smuggling',
    name: 'HTTP Request Smuggling',
    family: 'http-configuration',
    enabled: true,

    /*
     * Never perform generic request-desynchronization attacks
     * against a project runtime.
     */
    activeProbe: false,

    aliases: [
      'request smuggling',
      'http request smuggling',
      'http desync',
      'cl.te',
      'te.cl',
    ],

    methods: [
      'POST',
    ],

    inputLocations: [
      'header',
      'body',
    ],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'request_smuggling',
  },

  {
    id: 'cache_poisoning',
    name: 'Web Cache Poisoning',
    family: 'http-configuration',
    enabled: true,
    activeProbe: false,

    aliases: [
      'cache poisoning',
      'web cache poisoning',
      'cache key poisoning',
      'cache deception',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [
      'header',
      'query',
    ],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'cache_poisoning',
  },
];