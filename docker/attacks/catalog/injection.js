'use strict';

module.exports = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'sql injection',
      'sql-injection',
      'sqli',
      'database injection',
      'query injection',
    ],

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
    ],

    inputLocations: [
      'query',
      'body',
      'path',
    ],

    routeHints: [
      'search',
      'login',
      'user',
      'product',
      'item',
      'filter',
    ],

    parameterHints: [
      'id',
      'user',
      'userId',
      'username',
      'name',
      'search',
      'query',
      'q',
      'filter',
      'sort',
      'category',
      'product',
      'item',
    ],

    payloads: [
      "' OR '1'='1",
      "' AND '1'='2",
      "' OR 1=1 --",
    ],

    validator: 'sqli',
  },

  {
    id: 'nosqli',
    name: 'NoSQL Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'nosql injection',
      'nosql-injection',
      'nosqli',
      'mongodb injection',
      'mongo injection',
    ],

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
    ],

    inputLocations: [
      'query',
      'body',
      'json',
    ],

    routeHints: [
      'search',
      'login',
      'user',
      'filter',
    ],

    parameterHints: [
      'user',
      'username',
      'name',
      'search',
      'query',
      'q',
      'filter',
      'id',
    ],

    payloads: [
      '{"$ne":null}',
      '{"$gt":""}',
    ],

    validator: 'nosqli',
  },

  {
    id: 'cmdi',
    name: 'Command Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'command injection',
      'command-injection',
      'shell injection',
      'os command injection',
      'cmd injection',
      'cmdi',
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
      'ping',
      'diagnostic',
      'command',
      'exec',
      'host',
    ],

    parameterHints: [
      'host',
      'hostname',
      'ip',
      'command',
      'cmd',
      'target',
      'address',
    ],

    payloads: [
      'localhost;whoami',
      'localhost&&whoami',
      'localhost|whoami',
    ],

    validator: 'cmdi',
  },

  {
    id: 'code_injection',
    name: 'Code Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'code injection',
      'code-injection',
      'eval injection',
      'dynamic code execution',
      'remote code execution',
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
      'eval',
      'execute',
      'code',
      'expression',
    ],

    parameterHints: [
      'code',
      'expression',
      'expr',
      'script',
      'value',
    ],

    payloads: [
      'process.env',
    ],

    validator: 'code_injection',
  },

  {
    id: 'ssti',
    name: 'Server-Side Template Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'server side template injection',
      'server-side template injection',
      'template injection',
      'ssti',
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
      'template',
      'render',
      'preview',
      'message',
    ],

    parameterHints: [
      'template',
      'name',
      'message',
      'text',
      'content',
      'value',
    ],

    payloads: [
      '{{7*7}}',
      '${7*7}',
    ],

    validator: 'ssti',
  },

  {
    id: 'ldap_injection',
    name: 'LDAP Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'ldap injection',
      'ldap-injection',
      'ldap filter injection',
      'directory query injection',
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
      'ldap',
      'directory',
      'user',
      'search',
      'login',
    ],

    parameterHints: [
      'user',
      'username',
      'name',
      'filter',
      'search',
      'query',
      'uid',
    ],

    payloads: [
      '*)(uid=*))(|(uid=*',
      '*)(|(uid=*))',
    ],

    validator: 'ldap_injection',
  },

  {
    id: 'xpath_injection',
    name: 'XPath Injection',
    family: 'injection',
    enabled: true,
    activeProbe: true,

    aliases: [
      'xpath injection',
      'xpath-injection',
      'xml query injection',
      'xpath query injection',
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
      'xml',
      'xpath',
      'search',
      'login',
      'user',
    ],

    parameterHints: [
      'user',
      'username',
      'name',
      'search',
      'query',
      'id',
    ],

    payloads: [
      "' or '1'='1",
      "' or ''='",
    ],

    validator: 'xpath_injection',
  },

  {
    id: 'xxe',
    name: 'XML External Entity',
    family: 'injection',
    enabled: true,

    // Generic real-project XXE probes are deliberately disabled.
    // Safe Simulation has a deterministic synthetic fixture.
    activeProbe: false,

    aliases: [
      'xxe',
      'xml external entity',
      'external entity injection',
      'xml entity injection',
    ],

    methods: [
      'POST',
    ],

    inputLocations: [
      'body',
      'xml',
    ],

    routeHints: [
      'xml',
      'import',
      'document',
      'feed',
    ],

    parameterHints: [
      'xml',
      'document',
      'data',
      'payload',
    ],

    payloads: [],

    validator: 'xxe',
  },

  {
    id: 'prototype_pollution',
    name: 'Prototype Pollution',
    family: 'injection',
    enabled: true,

    // Do not mutate real application/global object state
    // during generic Project Validation.
    activeProbe: false,

    aliases: [
      'prototype pollution',
      'prototype-pollution',
      '__proto__ pollution',
      'constructor prototype pollution',
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
      'config',
      'options',
      'settings',
      'merge',
    ],

    parameterHints: [
      '__proto__',
      'constructor',
      'prototype',
      'options',
      'config',
    ],

    payloads: [],

    validator: 'prototype_pollution',
  },

  {
    id: 'insecure_deserialization',
    name: 'Insecure Deserialization',
    family: 'injection',
    enabled: true,

    activeProbe: false,

    aliases: [
      'insecure deserialization',
      'unsafe deserialization',
      'deserialization vulnerability',
      'object deserialization',
    ],

    methods: [
      'POST',
    ],

    inputLocations: [
      'body',
      'cookie',
      'header',
    ],

    routeHints: [
      'deserialize',
      'object',
      'state',
      'session',
      'import',
    ],

    parameterHints: [
      'data',
      'object',
      'serialized',
      'state',
      'session',
    ],

    payloads: [],

    validator: 'insecure_deserialization',
  },
];