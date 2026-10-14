'use strict';

module.exports = [
  {
    id: 'sensitive_data',
    name: 'Sensitive Data Exposure',
    family: 'exposure',
    enabled: true,
    activeProbe: false,

    aliases: [
      'sensitive data exposure',
      'information disclosure',
      'secret exposure',
      'credential exposure',
      'data leakage',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'sensitive_data',
  },

  {
    id: 'debug_exposure',
    name: 'Debug Information Exposure',
    family: 'exposure',
    enabled: true,
    activeProbe: false,

    aliases: [
      'debug exposure',
      'debug mode',
      'stack trace',
      'error disclosure',
      'configuration exposure',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [],

    routeHints: [],

    parameterHints: [],

    payloads: [],

    validator: 'debug_exposure',
  },

  {
    id: 'directory_listing',
    name: 'Directory Listing',
    family: 'exposure',
    enabled: true,
    activeProbe: false,

    aliases: [
      'directory listing',
      'directory indexing',
      'index of',
    ],

    methods: [
      'GET',
    ],

    inputLocations: [],

    routeHints: [
      'files',
      'uploads',
      'assets',
      'static',
      'backup',
    ],

    parameterHints: [],

    payloads: [],

    validator: 'directory_listing',
  },
];