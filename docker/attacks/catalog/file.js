'use strict';

module.exports = [
  {
    id: 'path_traversal',
    name: 'Path Traversal',
    family: 'file',
    enabled: true,
    activeProbe: false,

    aliases: [
      'path traversal',
      'directory traversal',
      'directory-traversal',
      'path-traversal',
    ],

    methods: [
      'GET',
      'POST',
    ],

    inputLocations: [
      'query',
      'body',
      'path',
    ],

    routeHints: [
      'file',
      'download',
      'document',
      'asset',
      'path',
    ],

    parameterHints: [
      'file',
      'filename',
      'path',
      'document',
      'download',
      'name',
    ],

    // Project Validation must use a target-owned canary and explicit opt-in.
    payloads: [],

    validator: 'path_traversal',
  },

  {
    id: 'lfi',
    name: 'Local File Inclusion',
    family: 'file',
    enabled: true,
    activeProbe: false,

    aliases: [
      'local file inclusion',
      'local-file-inclusion',
      'lfi',
      'file inclusion',
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
      'include',
      'template',
      'file',
      'page',
      'document',
    ],

    parameterHints: [
      'file',
      'filename',
      'path',
      'page',
      'template',
      'include',
    ],

    // Requires a target-owned canary and explicit runtime contract.
    payloads: [],

    validator: 'lfi',
  },

  {
    id: 'file_upload',
    name: 'Unsafe File Upload',
    family: 'file',
    enabled: true,

    /*
     * Generic Project Validation must not leave files behind.
     * Safe Simulation uses a synthetic no-write fixture.
     */
    activeProbe: false,

    aliases: [
      'file upload',
      'unsafe file upload',
      'unrestricted file upload',
      'arbitrary file upload',
      'malicious file upload',
    ],

    methods: [
      'POST',
    ],

    inputLocations: [
      'body',
      'multipart',
    ],

    routeHints: [
      'upload',
      'attachment',
      'file',
      'media',
      'image',
      'document',
    ],

    parameterHints: [
      'file',
      'upload',
      'attachment',
      'document',
      'image',
    ],

    payloads: [],

    validator: 'file_upload',
  },
];