'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  parseCryptoFile,
  buildSecurityAuditMarkdown,
  buildKeySetDiffMarkdown,
  buildComplianceCsv,
  buildComplianceMarkdown,
} = require('../src/crypto-parse');
const { CryptoViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

function makeJwt(header, payload) {
  const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${b64u(header)}.${b64u(payload)}.signatureSegment123`;
}

describe('JWT, JWKS & X.509 parser', () => {
  it('decodes JWT and flags alg:none, HS256, expired and sensitive claims', () => {
    const tok1 = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'user-1', exp: 1000, user_password: 'abc' });
    const tok2 = makeJwt({ alg: 'HS256', kid: 'k1' }, { sub: 'user-2', exp: 4102444800 });
    const parsed = parseCryptoFile(`${tok1}\n${tok2}\n`, 'tokens.jwt', { nowMs: 1700000000000 });
    assert.equal(parsed.stats.itemCount, 2);
    assert.ok(parsed.findings.some((f) => f.category === 'Algorithm' && f.severity === 'error'));
    assert.ok(parsed.findings.some((f) => f.category === 'Algorithm' && f.severity === 'warning'));
    assert.ok(parsed.findings.some((f) => f.category === 'Expiry' && f.severity === 'error'));
    assert.ok(parsed.findings.some((f) => f.category === 'Sensitive Claim'));
  });

  it('decodes JWKS, flags duplicate kid and private key material', () => {
    const jwks = JSON.stringify({
      keys: [
        { kty: 'EC', crv: 'P-256', kid: 'dup-1', use: 'sig', alg: 'ES256', x: 'aa', y: 'bb' },
        { kty: 'EC', crv: 'P-256', kid: 'dup-1', use: 'sig', alg: 'ES256', x: 'aa', y: 'bb', d: 'secret-d' },
      ],
    });
    const parsed = parseCryptoFile(jwks, 'keys.jwks');
    assert.equal(parsed.stats.itemCount, 2);
    assert.ok(parsed.findings.some((f) => f.category === 'Duplicate KID'));
    assert.ok(parsed.findings.some((f) => f.category === 'Private Key'));
    assert.equal(parsed.items[1].raw.d, '[PRIVATE_KEY_REDACTED]');
  });

  it('parses the bundled sample.jwks file cleanly', () => {
    const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'sample.jwks'));
    const parsed = parseCryptoFile(buf, 'sample.jwks');
    assert.equal(parsed.format, 'JWKS Key Set');
    assert.equal(parsed.stats.itemCount, 3);
    assert.equal(parsed.stats.warningCount, 1);
  });

  it('decodes a real self-signed X.509 PEM certificate via openssl', () => {
    const res = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-keyout', '/dev/null', '-subj', '/CN=test.zovo.local', '-days', '10',
    ], { encoding: 'utf8' });
    if (res.status === 0 && res.stdout.includes('BEGIN CERTIFICATE')) {
      const parsed = parseCryptoFile(res.stdout, 'test.pem', { expiryWarnDays: 30 });
      assert.equal(parsed.items[0].kind, 'X.509');
      assert.equal(parsed.items[0].id, 'test.zovo.local');
      assert.ok(parsed.findings.some((f) => f.category === 'Self-Signed'));
      assert.ok(parsed.findings.some((f) => f.category === 'Expiry'));
    }
  });

  it('builds audit, diff and compliance CSV/Markdown outputs', () => {
    const left = parseCryptoFile(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'k1', use: 'sig', alg: 'ES256' }] }), 'a.jwks');
    const right = parseCryptoFile(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'k1', use: 'sig', alg: 'ES256' }, { kty: 'OKP', crv: 'Ed25519', kid: 'k2', use: 'sig', alg: 'EdDSA' }] }), 'b.jwks');
    const audit = buildSecurityAuditMarkdown([{ fileName: 'a.jwks', parsed: left }]);
    assert.ok(audit.includes('# JWT, JWKS & X.509 Security & Expiry Audit'));
    const diff = buildKeySetDiffMarkdown('a.jwks', left, 'b.jwks', right);
    assert.ok(diff.includes('| `JWK:k2` | Added |'));
    const csv = buildComplianceCsv(right, 'b.jwks');
    assert.ok(csv.includes('b.jwks,2,JWK,k2,EdDSA'));
    const md = buildComplianceMarkdown(right, 'b.jwks');
    assert.ok(md.includes('# Compliance Inventory: b.jwks'));
  });
});

describe('CryptoViewModel and HTML CSP', () => {
  it('filters items and returns detail payload', () => {
    const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'sample.jwks'));
    const parsed = parseCryptoFile(buf, 'sample.jwks');
    const vm = new CryptoViewModel(parsed, 'sample.jwks', buf.length);
    assert.equal(vm.totalCount(), 3);
    assert.equal(vm.setFilter({ text: 'eddsa' }), 1);
    assert.equal(vm.rows(0, 10).length, 1);
    assert.equal(vm.detail(2).id, 'edge-eddsa-2026-02');
  });

  it('renders strict CSP without unsafe-inline', () => {
    const policy = csp('vscode-webview://x', 'nonce456');
    assert.ok(policy.includes("default-src 'none'"));
    assert.ok(!policy.includes('unsafe-inline'));
    const html = editorHtml({ cspSource: 'vscode-webview://x', script: 'viewer.js', styleUri: 'viewer.css', title: 'sample.jwks', nonce: 'nonce456' });
    assert.ok(html.includes('nonce="nonce456"'));
  });
});
