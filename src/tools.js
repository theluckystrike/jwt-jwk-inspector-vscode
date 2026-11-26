'use strict';
// Pro tools for JWT, JWKS & X.509 Cert Inspector:
//   1. auditSecurity: Offline security & expiry Markdown report across one file or folder.
//   2. diffKeySets: Compare two JWKS, JWT or certificate files in Markdown.
//   3. exportComplianceReport: Non-destructive CSV and Markdown compliance inventory export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseCryptoFile,
  buildSecurityAuditMarkdown,
  buildKeySetDiffMarkdown,
  buildComplianceCsv,
  buildComplianceMarkdown,
} = require('./crypto-parse');

const CRYPTO_FILE_RE = /\.(jwt|jwks|jwk|pem|crt|cer)$/i;
const CRYPTO_FILTERS = { 'JWT, JWKS & X.509 Files': ['jwt', 'jwks', 'jwk', 'pem', 'crt', 'cer'] };

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select JWT, JWKS or certificate file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && CRYPTO_FILE_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: CRYPTO_FILTERS,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listCryptoFilesInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && CRYPTO_FILE_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditSecurity(uri, opts = {}) {
    if (!(await pro.allowed('auditSecurity', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listCryptoFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No JWT, JWKS or X.509 certificate files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      entries.push({ fileName: path.basename(f), parsed: parseCryptoFile(buf, path.basename(f)) });
    }
    const md = buildSecurityAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditSecurity');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffKeySets(uri, opts = {}) {
    if (!(await pro.allowed('diffKeySets', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline JWKS, JWT or certificate file');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: CRYPTO_FILTERS,
        openLabel: 'Select second JWKS, JWT or certificate file to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildKeySetDiffMarkdown(
      leftName,
      parseCryptoFile(leftBuf, leftName),
      rightName,
      parseCryptoFile(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffKeySets');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportComplianceReport(uri, opts = {}) {
    if (!(await pro.allowed('exportComplianceReport', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseCryptoFile(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(CRYPTO_FILE_RE, '') || 'keys';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}-compliance.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'Compliance Inventory CSV': ['csv'] },
        saveLabel: 'Save compliance inventory',
      });
    if (!saveUri) return undefined;

    const csvPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(csvPath);
    const stem = path.basename(csvPath, '.csv').replace(/-compliance$/i, '');
    const mdPath = uniquePath(path.join(dir, `${stem}-compliance.md`));

    fs.writeFileSync(csvPath, buildComplianceCsv(parsed, baseName), 'utf8');
    fs.writeFileSync(mdPath, buildComplianceMarkdown(parsed, baseName), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportComplianceReport');
    if (reach) reach.refresh();
    return { files: [csvPath, mdPath], items: parsed.stats.itemCount };
  }

  return { auditSecurity, diffKeySets, exportComplianceReport };
}

module.exports = { createTools, uniquePath, listCryptoFilesInDir };
