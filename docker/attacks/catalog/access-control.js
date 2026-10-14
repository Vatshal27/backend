'use strict';

module.exports = [
  {
    id: 'auth_bypass',
    name: 'Authentication Bypass',
    family: 'authentication',
    enabled: true,
    activeProbe: true,

    aliases: [
      'authentication bypass',
      'auth bypass',
      'unauthenticated access',
      'missing authentication',
      'missing auth',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [],

    routeHints: [
      'admin',
      'dashboard',
      'account',
      'profile',
      'manage',
      'management',
      'settings',
      'private',
      'secure',
      'internal',
    ],

    parameterHints: [],

    payloads: [],

    validator: 'auth_bypass',
  },

  {
    id: 'idor',
    name: 'IDOR / BOLA',
    family: 'authorization',
    enabled: true,
    activeProbe: false,

    aliases: [
      'idor',
      'bola',
      'insecure direct object reference',
      'broken object level authorization',
      'object authorization',
    ],

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
    ],

    inputLocations: [
      'path',
      'query',
      'body',
    ],

    routeHints: [
      'user',
      'account',
      'object',
      'order',
      'profile',
      'document',
    ],

    parameterHints: [
      'id',
      'userId',
      'accountId',
      'objectId',
      'orderId',
      'documentId',
    ],

    payloads: [],

    validator: 'idor',
  },

  {
    id: 'jwt',
    name: 'JWT Security',
    family: 'authentication',
    enabled: true,
    activeProbe: false,

    aliases: [
      'jwt',
      'json web token',
      'jwt security',
      'jwt validation',
      'token validation',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'header',
      'cookie',
    ],

    routeHints: [
      'auth',
      'token',
      'session',
      'api',
    ],

    parameterHints: [
      'authorization',
      'token',
      'jwt',
    ],

    payloads: [],

    validator: 'jwt',
  },

  {
    id: 'csrf',
    name: 'Cross-Site Request Forgery',
    family: 'authorization',
    enabled: true,
    activeProbe: false,

    aliases: [
      'csrf',
      'cross site request forgery',
      'cross-site request forgery',
      'missing csrf protection',
      'csrf protection',
    ],

    methods: [
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
    ],

    inputLocations: [
      'body',
      'header',
      'cookie',
    ],

    routeHints: [
      'account',
      'settings',
      'profile',
      'update',
      'change',
      'delete',
      'transfer',
    ],

    parameterHints: [
      'csrf',
      'csrf_token',
      '_csrf',
      'token',
    ],

    payloads: [],

    validator: 'csrf',
  },

  {
    id: 'mass_assignment',
    name: 'Mass Assignment',
    family: 'authorization',
    enabled: true,
    activeProbe: false,

    aliases: [
      'mass assignment',
      'mass-assignment',
      'overposting',
      'unsafe object binding',
    ],

    methods: [
      'POST',
      'PUT',
      'PATCH',
    ],

    inputLocations: [
      'body',
      'json',
    ],

    routeHints: [
      'user',
      'profile',
      'account',
      'update',
      'settings',
    ],

    parameterHints: [
      'role',
      'admin',
      'isAdmin',
      'permissions',
      'privilege',
      'owner',
    ],

    payloads: [],

    validator: 'mass_assignment',
  },

  {
    id: 'race_condition',
    name: 'Race Condition',
    family: 'authorization',
    enabled: true,
    activeProbe: false,

    aliases: [
      'race condition',
      'race-condition',
      'concurrent request flaw',
      'double submit',
      'toctou',
      'time of check time of use',
    ],

    methods: [
      'POST',
      'PUT',
      'PATCH',
    ],

    inputLocations: [
      'body',
    ],

    routeHints: [
      'transfer',
      'payment',
      'purchase',
      'redeem',
      'claim',
      'checkout',
    ],

    parameterHints: [],

    payloads: [],

    validator: 'race_condition',
  },

  {
    id: 'business_logic',
    name: 'Business Logic Flaw',
    family: 'authorization',
    enabled: true,
    activeProbe: false,

    aliases: [
      'business logic',
      'business logic flaw',
      'workflow bypass',
      'logic vulnerability',
      'business rule bypass',
      'workflow vulnerability',
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
      'checkout',
      'purchase',
      'payment',
      'approval',
      'workflow',
      'redeem',
      'order',
    ],

    parameterHints: [],

    payloads: [],

    validator: 'business_logic',
  },
];