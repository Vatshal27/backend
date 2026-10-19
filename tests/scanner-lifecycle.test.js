'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('scanner command captures independent tool exit states and parser retains coverage', () => {
    const { buildScannerCommand, extractScannerResult } = require('../docker-scanner');
    const command = buildScannerCommand(2);
    assert.match(command, /semgrep-exit-code/);
    assert.match(command, /bandit-exit-code/);
    const logs = Buffer.from('__SENTINEL_RESULT_START__\n' + JSON.stringify({
        semgrep: [], bandit: [], filesScanned: 2,
        coverage: { status: 'inconclusive', tools: { semgrep: { status: 'failed', exitCode: 127 }, bandit: { status: 'complete', exitCode: 1 } } },
    }) + '\n__SENTINEL_RESULT_END__');
    const result = extractScannerResult(logs);
    assert.equal(result.coverage.status, 'inconclusive');
    assert.equal(result.coverage.tools.semgrep.status, 'failed');
    assert.equal(result.coverage.tools.bandit.status, 'complete');
});
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const scannerPath = path.resolve(__dirname, '../docker-scanner.js');
const realRequire = createRequire(scannerPath);
const files = [{ path: 'fixture.py', code: 'password = "fixture-not-a-real-password"\n' }];

function harness(overrides = {}) {
    const state = { events: [], removes: 0, starts: 0, creates: 0, directories: [] };
    const container = {
        start: async () => { state.starts++; },
        wait: async () => ({ StatusCode: 0 }),
        logs: async () => Buffer.from('__SENTINEL_RESULT_START__\n' + JSON.stringify({ semgrep: [], bandit: [], filesScanned: 1, coverage: { status: 'complete', tools: { semgrep: { status: 'complete', diagnostics: '' }, bandit: { status: 'complete', diagnostics: '' } } } }) + '\n__SENTINEL_RESULT_END__'),
        remove: async () => { state.removes++; },
        ...overrides.container,
    };
    const docker = {
        getImage: () => ({ inspect: async () => ({}) }),
        createContainer: async config => {
            state.creates++;
            state.config = config;
            state.directory = config.HostConfig.Binds[0].split(':/workspace:ro')[0];
            state.source = fs.readFileSync(path.join(state.directory, files[0].path), 'utf8');
            return container;
        },
        ...overrides.docker,
    };
    const fakeFs = Object.assign({}, fs, {
        mkdtempSync: prefix => { const dir = fs.mkdtempSync(prefix); state.directories.push(dir); return dir; },
        ...overrides.fs,
    });
    const sandbox = { module: { exports: {} }, console: { log() {}, warn() {}, error() {} }, process: { env: { ...process.env, SENTINEL_SCANNER_TIMEOUT: '1000' } }, Buffer, setTimeout, clearTimeout, require: name => name === 'dockerode' ? function Docker() { return docker; } : name === 'fs' ? fakeFs : realRequire(name) };
    vm.runInNewContext(fs.readFileSync(scannerPath, 'utf8'), sandbox, { filename: scannerPath });
    return { ...sandbox.module.exports, state, options: { onEvent: event => state.events.push(event) } };
}

test('pre-aborted scans reject without creating a container', async () => {
    const h = harness();
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(h.runStaticAnalysis(files, { ...h.options, signal: controller.signal }), { name: 'AbortError' });
    assert.equal(h.state.creates, 0);
});

test('active cancellation removes the scanner and its temporary source directory', async () => {
    const controller = new AbortController();
    const h = harness({ container: { wait: () => { controller.abort(); return new Promise(() => {}); } } });
    await assert.rejects(h.runStaticAnalysis(files, { ...h.options, signal: controller.signal }), { name: 'AbortError' });
    assert.equal(h.state.removes, 1);
    assert.equal(fs.existsSync(h.state.directory), false);
    assert.equal(h.state.events.at(-1).status, 'cancelled');
    assert.ok(!h.state.events.some(event => event.status === 'complete'));
});

test('temporary sources are removed when preparation fails', async () => {
    const h = harness({ fs: { writeFileSync: () => { throw new Error('fixture write failed'); } } });
    try {
        await assert.rejects(h.runStaticAnalysis(files), /fixture write failed/);
        assert.ok(h.state.directories.every(dir => !fs.existsSync(dir)));
    } finally {
        h.state.directories.forEach(dir => fs.rmSync(dir, { recursive: true, force: true }));
    }
});

test('malformed scanner output rejects instead of returning a clean empty result', async () => {
    const h = harness({ container: { logs: async () => Buffer.from('password="never-log-this-fixture"') } });
    await assert.rejects(h.runStaticAnalysis(files, h.options), /no valid result/i);
    assert.equal(h.state.removes, 1);
    assert.equal(fs.existsSync(h.state.directory), false);
    assert.equal(h.state.events.at(-1).status, 'failed');
});
