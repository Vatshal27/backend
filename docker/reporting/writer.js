'use strict';

const fs =
  require(
    'node:fs/promises'
  );

const path =
  require(
    'node:path'
  );

const {
  createMachineReport,
} = require(
  './machine-report'
);

const {
  renderMarkdownReport,
} = require(
  './markdown-report'
);

const REPORT_MARKDOWN =
  'SentinelAI_Security_Report.md';

const REPORT_JSON =
  'SentinelAI_Security_Data.json';

const REPORT_TEMPORARIES = new Set();
let reportWriteQueue = Promise.resolve();

async function writeReportFiles(
  report,
  reportsDirOverride,
  io = fs
) {
  const reportsDir =
    reportsDirOverride || path.join(
      __dirname,
      '..',
      '..',
      'reports'
    );

  await fs.mkdir(
    reportsDir,
    {
      recursive:
        true,
    }
  );

  const previousWrite = reportWriteQueue;
  let releaseWrite;
  reportWriteQueue = new Promise(resolve => { releaseWrite = resolve; });
  await previousWrite;
  const reportLockPath = path.join(reportsDir, '.sentinelai-report-write.lock');
  let lockHandle;
  let lockIdentity;
  try {
    lockHandle = await io.open(reportLockPath, 'wx', 0o600);
    lockIdentity = await lockHandle.stat();
  } catch (error) {
    releaseWrite();
    if (error.code === 'EEXIST') throw new Error('A SentinelAI report update is already in progress.');
    throw error;
  }

  const markdownPath =
    path.join(
      reportsDir,
      REPORT_MARKDOWN
    );

  const jsonPath =
    path.join(
      reportsDir,
      REPORT_JSON
    );

  try {
  for (const filePath of [markdownPath, jsonPath]) {
    try {
      const existing = await fs.lstat(filePath);
      if (!existing.isFile() || existing.isSymbolicLink()) throw new Error(`Refusing to replace a non-regular report path: ${path.basename(filePath)}`);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const machineReport =
    createMachineReport(
      report
    );

  const markdown =
    renderMarkdownReport(
      report
    );

  const json =
    JSON.stringify(
      machineReport,
      null,
      2
    );

  let existingMarkdown;
  let existingJson;
  try { existingMarkdown = await fs.lstat(markdownPath); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  try { existingJson = await fs.lstat(jsonPath); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if ((existingMarkdown && (!existingMarkdown.isFile() || existingMarkdown.isSymbolicLink())) ||
      (existingJson && (!existingJson.isFile() || existingJson.isSymbolicLink()))) {
    throw new Error('Refusing to replace a non-regular report file.');
  }
  const suffix = `${process.pid}-${Date.now()}-${require('node:crypto').randomUUID()}`;
  const markdownTemp = `${markdownPath}.${suffix}.tmp`;
  const jsonTemp = `${jsonPath}.${suffix}.tmp`;
  const markdownBackup = `${markdownPath}.${suffix}.bak`;
  const jsonBackup = `${jsonPath}.${suffix}.bak`;
  let markdownInstalled = false;
  let jsonInstalled = false;
  let markdownBackedUp = false;
  let jsonBackedUp = false;
  let committed = false;
  [markdownTemp, jsonTemp, markdownBackup, jsonBackup].forEach(file => REPORT_TEMPORARIES.add(path.basename(file)));
  try {
    await fs.writeFile(markdownTemp, markdown, { encoding: 'utf8', flag: 'wx' });
    await fs.writeFile(jsonTemp, json, { encoding: 'utf8', flag: 'wx' });
    if (existingMarkdown) { await fs.rename(markdownPath, markdownBackup); markdownBackedUp = true; }
    if (existingJson) { await fs.rename(jsonPath, jsonBackup); jsonBackedUp = true; }
    await fs.rename(markdownTemp, markdownPath); markdownInstalled = true;
    await fs.rename(jsonTemp, jsonPath); jsonInstalled = true;
    committed = true;
  } catch (error) {
    if (markdownInstalled) await fs.rm(markdownPath, { force: true }).catch(() => {});
    if (jsonInstalled) await fs.rm(jsonPath, { force: true }).catch(() => {});
    const restoreFailures = [];
    if (markdownBackedUp) await fs.rename(markdownBackup, markdownPath).catch(restoreError => restoreFailures.push(restoreError.message));
    if (jsonBackedUp) await fs.rename(jsonBackup, jsonPath).catch(restoreError => restoreFailures.push(restoreError.message));
    if (restoreFailures.length) error.message += ` Report rollback incomplete; preserve recovery files ${markdownBackup} and ${jsonBackup}.`;
    throw error;
  } finally {
    await Promise.all([
      fs.rm(markdownTemp, { force: true }).catch(() => {}),
      fs.rm(jsonTemp, { force: true }).catch(() => {}),
      ...(committed ? [fs.rm(markdownBackup, { force: true }).catch(() => {}), fs.rm(jsonBackup, { force: true }).catch(() => {})] : []),
    ]);
    if (committed || (!markdownBackedUp && !jsonBackedUp) || (markdownBackedUp && jsonBackedUp)) {
      [markdownTemp, jsonTemp, markdownBackup, jsonBackup].forEach(file => REPORT_TEMPORARIES.delete(path.basename(file)));
    }
  }

  return {
    markdown:
      markdownPath,
    json:
      jsonPath,
    generatedAt:
      machineReport
        .generatedAt,
    expiresAt:
      machineReport
        .expiresAt,
    timeZone:
      machineReport
        .timeZone,
  };
  } finally {
    await lockHandle.close().catch(() => {});
    const currentStat = await io.stat(reportLockPath).catch(() => null);
    if (currentStat?.ino === lockIdentity?.ino && currentStat?.dev === lockIdentity?.dev) await io.unlink(reportLockPath).catch(() => {});
    releaseWrite();
  }
}

module.exports = {
  writeReportFiles,
  getManagedReportFiles: () => new Set([...REPORT_TEMPORARIES, REPORT_MARKDOWN, REPORT_JSON]),
};