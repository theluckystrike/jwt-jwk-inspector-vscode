'use strict';
// Offline parser & security analyzer for .jwt, .jwks, .jwk, .pem, .crt, .cer files.
// Uses built-in Node crypto.X509Certificate and plain JS. Zero external deps, zero network.
const crypto = require('crypto');

const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];
const SENSITIVE_CLAIM_RE = /(password|passwd|secret|private_key|api_key|client_secret)/i;

function b64urlDecode(segment) {
  const norm = String(segment || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
  return Buffer.from(norm + pad, 'base64').toString('utf8');
}

function fmtIso(sec) {
  if (typeof sec !== 'number' || !Number.isFinite(sec)) return '-';
  return new Date(sec * 1000).toISOString();
}

function daysBetween(fromMs, toMs) {
  return Math.floor((toMs - fromMs) / 86400000);
}

function parseJwtToken(token, index, nowMs, warnDays) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format (expected 3 dot-separated segments).');
  const header = JSON.parse(b64urlDecode(parts[0]));
  const payload = JSON.parse(b64urlDecode(parts[1]));
  const alg = String(header.alg || 'unknown');
  const kid = header.kid ? String(header.kid) : '-';
  const typ = String(header.typ || 'JWT');
  const findings = [];

  if (alg.toLowerCase() === 'none' || !header.alg) {
    findings.push({
      severity: 'error',
      category: 'Algorithm',
      item: `JWT #${index}`,
      finding: `Insecure JWT algorithm "${alg}". Never accept unsigned "alg: none" tokens.`,
    });
  } else if (/^HS256$/i.test(alg)) {
    findings.push({
      severity: 'warning',
      category: 'Algorithm',
      item: `JWT #${index}`,
      finding: 'Symmetric HS256 algorithm detected. Prefer asymmetric RS256, ES256 or EdDSA for distributed verification.',
    });
  }

  let validity = 'No exp claim';
  if (typeof payload.exp === 'number') {
    const expMs = payload.exp * 1000;
    const days = daysBetween(nowMs, expMs);
    if (expMs < nowMs) {
      validity = `Expired (${fmtIso(payload.exp)})`;
      findings.push({
        severity: 'error',
        category: 'Expiry',
        item: `JWT #${index}`,
        finding: `Token expired on ${fmtIso(payload.exp)}.`,
      });
    } else if (days <= warnDays) {
      validity = `Expires in ${days}d (${fmtIso(payload.exp)})`;
      findings.push({
        severity: 'warning',
        category: 'Expiry',
        item: `JWT #${index}`,
        finding: `Token expires within ${days} day(s) (${fmtIso(payload.exp)}).`,
      });
    } else {
      validity = `Valid until ${fmtIso(payload.exp)}`;
    }
  } else {
    findings.push({
      severity: 'warning',
      category: 'Expiry',
      item: `JWT #${index}`,
      finding: 'JWT payload has no "exp" expiration claim.',
    });
  }

  if (typeof payload.nbf === 'number' && payload.nbf * 1000 > nowMs) {
    findings.push({
      severity: 'warning',
      category: 'NotBefore',
      item: `JWT #${index}`,
      finding: `Token is not valid before ${fmtIso(payload.nbf)}.`,
    });
  }

  for (const k of Object.keys(payload)) {
    if (SENSITIVE_CLAIM_RE.test(k)) {
      findings.push({
        severity: 'error',
        category: 'Sensitive Claim',
        item: `JWT #${index}`,
        finding: `JWT payload contains sensitive claim "${k}". JWT payloads are base64-encoded, not encrypted.`,
      });
    }
  }

  const errCount = findings.filter((f) => f.severity === 'error').length;
  const warnCount = findings.filter((f) => f.severity === 'warning').length;
  const label = payload.sub ? `sub=${payload.sub}` : (payload.iss ? `iss=${payload.iss}` : `JWT #${index}`);

  return {
    index,
    kind: 'JWT',
    id: kid !== '-' ? kid : label,
    label,
    alg,
    use: typ,
    validity,
    status: errCount > 0 ? 'error' : (warnCount > 0 ? 'warning' : 'ok'),
    errorCount: errCount,
    warningCount: warnCount,
    findings,
    meta: {
      type: 'JWT',
      kid,
      typ,
      alg,
      iss: payload.iss || '-',
      sub: payload.sub || '-',
      aud: Array.isArray(payload.aud) ? payload.aud.join(', ') : (payload.aud || '-'),
      iat: fmtIso(payload.iat),
      nbf: fmtIso(payload.nbf),
      exp: fmtIso(payload.exp),
      signatureLength: parts[2].length,
    },
    raw: { header, payload },
  };
}

function parseJwkObject(jwk, index, seenKids) {
  const kid = jwk.kid ? String(jwk.kid) : `(unnamed-${index})`;
  const kty = String(jwk.kty || 'unknown');
  const use = String(jwk.use || (Array.isArray(jwk.key_ops) ? jwk.key_ops.join(',') : '-'));
  const alg = String(jwk.alg || '-');
  const findings = [];

  if (!jwk.kid) {
    findings.push({
      severity: 'warning',
      category: 'Key ID',
      item: kid,
      finding: 'JWK entry is missing a "kid" key identifier.',
    });
  } else if (seenKids.has(kid)) {
    findings.push({
      severity: 'error',
      category: 'Duplicate KID',
      item: kid,
      finding: `Duplicate "kid" value "${kid}" found in JWKS.`,
    });
  } else {
    seenKids.add(kid);
  }

  if (alg.toLowerCase() === 'none') {
    findings.push({
      severity: 'error',
      category: 'Algorithm',
      item: kid,
      finding: 'JWK specifies insecure "alg: none".',
    });
  } else if (/^HS256$/i.test(alg) || kty === 'oct') {
    findings.push({
      severity: 'warning',
      category: 'Algorithm',
      item: kid,
      finding: `Symmetric key material (${kty}/${alg}) in JWKS. Public JWKS endpoints should only publish asymmetric public keys.`,
    });
  }

  const privFields = PRIVATE_JWK_FIELDS.filter((f) => jwk[f] !== undefined && jwk[f] !== '');
  if (privFields.length) {
    findings.push({
      severity: 'error',
      category: 'Private Key',
      item: kid,
      finding: `JWK contains private key fields (${privFields.join(', ')}). Never publish private key parameters in a public JWKS.`,
    });
  }

  // Estimate RSA modulus bit length if n is present
  let keyBits = '-';
  if (kty === 'RSA' && typeof jwk.n === 'string') {
    const norm = jwk.n.replace(/-/g, '+').replace(/_/g, '/');
    const buf = Buffer.from(norm, 'base64');
    keyBits = `${buf.length * 8} bits`;
    if (buf.length * 8 < 2048) {
      findings.push({
        severity: 'error',
        category: 'Weak Key',
        item: kid,
        finding: `RSA key size (${buf.length * 8} bits) is below 2048 bits.`,
      });
    }
  } else if (jwk.crv) {
    keyBits = String(jwk.crv);
  }

  const errCount = findings.filter((f) => f.severity === 'error').length;
  const warnCount = findings.filter((f) => f.severity === 'warning').length;
  const sanitizedRaw = { ...jwk };
  for (const pf of privFields) sanitizedRaw[pf] = '[PRIVATE_KEY_REDACTED]';

  return {
    index,
    kind: 'JWK',
    id: kid,
    label: `${kty} (${keyBits})`,
    alg: alg !== '-' ? alg : kty,
    use,
    validity: privFields.length ? 'Contains private key' : 'Public key',
    status: errCount > 0 ? 'error' : (warnCount > 0 ? 'warning' : 'ok'),
    errorCount: errCount,
    warningCount: warnCount,
    findings,
    meta: {
      type: 'JWK',
      kid,
      kty,
      use,
      alg,
      keySizeOrCurve: keyBits,
      hasX5c: Array.isArray(jwk.x5c) && jwk.x5c.length > 0 ? `Yes (${jwk.x5c.length})` : 'No',
      hasPrivateMaterial: privFields.length > 0 ? `YES (${privFields.join(', ')})` : 'No',
    },
    raw: sanitizedRaw,
  };
}

function parseX509Block(pemText, index, nowMs, warnDays) {
  const cert = new crypto.X509Certificate(pemText);
  const subject = cert.subject.replace(/\n/g, ', ');
  const issuer = cert.issuer.replace(/\n/g, ', ');
  const validFromMs = Date.parse(cert.validFrom);
  const validToMs = Date.parse(cert.validTo);
  const selfSigned = cert.subject === cert.issuer;
  const san = cert.subjectAltName || '-';
  const pubType = cert.publicKey ? cert.publicKey.asymmetricKeyType : 'unknown';
  const keyDetails = cert.publicKey && cert.publicKey.asymmetricKeyDetails ? cert.publicKey.asymmetricKeyDetails : {};
  const keySize = keyDetails.modulusLength ? `${keyDetails.modulusLength} bits` : (keyDetails.namedCurve || '-');
  const cnMatch = subject.match(/CN=([^,]+)/);
  const shortId = cnMatch ? cnMatch[1].trim() : `Cert #${index}`;

  const findings = [];
  let validity = `Valid until ${new Date(validToMs).toISOString().slice(0, 10)}`;

  if (Number.isFinite(validToMs) && validToMs < nowMs) {
    validity = `Expired (${new Date(validToMs).toISOString().slice(0, 10)})`;
    findings.push({
      severity: 'error',
      category: 'Expiry',
      item: shortId,
      finding: `X.509 certificate "${shortId}" expired on ${cert.validTo}.`,
    });
  } else if (Number.isFinite(validToMs)) {
    const days = daysBetween(nowMs, validToMs);
    if (days <= warnDays) {
      validity = `Expires in ${days}d`;
      findings.push({
        severity: 'warning',
        category: 'Expiry',
        item: shortId,
        finding: `X.509 certificate "${shortId}" expires in ${days} day(s) (${cert.validTo}).`,
      });
    }
  }

  if (Number.isFinite(validFromMs) && validFromMs > nowMs) {
    findings.push({
      severity: 'warning',
      category: 'NotBefore',
      item: shortId,
      finding: `X.509 certificate "${shortId}" is not valid until ${cert.validFrom}.`,
    });
  }

  if (selfSigned) {
    findings.push({
      severity: 'warning',
      category: 'Self-Signed',
      item: shortId,
      finding: `Certificate "${shortId}" is self-signed (subject matches issuer).`,
    });
  }

  if (pubType === 'rsa' && keyDetails.modulusLength && keyDetails.modulusLength < 2048) {
    findings.push({
      severity: 'error',
      category: 'Weak Key',
      item: shortId,
      finding: `RSA public key is ${keyDetails.modulusLength} bits (minimum recommended is 2048 bits).`,
    });
  }

  const errCount = findings.filter((f) => f.severity === 'error').length;
  const warnCount = findings.filter((f) => f.severity === 'warning').length;

  return {
    index,
    kind: 'X.509',
    id: shortId,
    label: subject,
    alg: `${pubType.toUpperCase()} (${keySize})`,
    use: selfSigned ? 'Self-signed' : 'CA-issued',
    validity,
    status: errCount > 0 ? 'error' : (warnCount > 0 ? 'warning' : 'ok'),
    errorCount: errCount,
    warningCount: warnCount,
    findings,
    meta: {
      type: 'X.509 Certificate',
      subject,
      issuer,
      subjectAltName: san,
      serialNumber: cert.serialNumber,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      selfSigned: selfSigned ? 'Yes' : 'No',
      publicKey: `${pubType} (${keySize})`,
      fingerprint256: cert.fingerprint256,
    },
    raw: {
      subject,
      issuer,
      subjectAltName: san,
      serialNumber: cert.serialNumber,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      selfSigned,
      fingerprint256: cert.fingerprint256,
    },
  };
}

function parseCryptoFile(input, fileName = 'keys.jwks', opts = {}) {
  const nowMs = typeof opts.nowMs === 'number' ? opts.nowMs : Date.now();
  const warnDays = Number(opts.expiryWarnDays) || 30;
  const text = (Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '')).trim();
  if (!text) throw new Error('File is empty.');

  const items = [];
  const findings = [];
  let format = 'Unknown';

  // 1. PEM / X.509 certificates or private key blocks
  const certBlocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  const privKeyBlocks = text.match(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g) || [];
  if (certBlocks.length || privKeyBlocks.length) {
    format = certBlocks.length > 1 ? 'X.509 PEM Bundle' : 'X.509 PEM Certificate';
    for (let i = 0; i < certBlocks.length; i += 1) {
      const item = parseX509Block(certBlocks[i], items.length + 1, nowMs, warnDays);
      items.push(item);
      findings.push(...item.findings);
    }
    for (let i = 0; i < privKeyBlocks.length; i += 1) {
      const f = {
        severity: 'error',
        category: 'Private Key',
        item: `Private Key #${i + 1}`,
        finding: 'PEM file contains a PRIVATE KEY block. Keep private keys out of shared repositories and bundles.',
      };
      findings.push(f);
      items.push({
        index: items.length + 1,
        kind: 'Private Key',
        id: `Private Key #${i + 1}`,
        label: 'PEM Private Key Block',
        alg: 'PRIVATE',
        use: 'Secret',
        validity: 'Sensitive material',
        status: 'error',
        errorCount: 1,
        warningCount: 0,
        findings: [f],
        meta: { type: 'PEM Private Key', status: 'Redacted for safety' },
        raw: { warning: 'Private key contents are hidden.' },
      });
    }
  } else if (text.startsWith('{') || text.startsWith('[')) {
    // 2. JWKS / JWK JSON
    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      throw new Error(`Invalid JSON in ${fileName}: ${e.message}`);
    }
    const seenKids = new Set();
    if (json && Array.isArray(json.keys)) {
      format = 'JWKS Key Set';
      for (let i = 0; i < json.keys.length; i += 1) {
        const item = parseJwkObject(json.keys[i] || {}, items.length + 1, seenKids);
        items.push(item);
        findings.push(...item.findings);
      }
    } else if (json && typeof json === 'object' && json.kty) {
      format = 'Single JWK';
      const item = parseJwkObject(json, 1, seenKids);
      items.push(item);
      findings.push(...item.findings);
    } else if (Array.isArray(json)) {
      format = 'JWK Array';
      for (let i = 0; i < json.length; i += 1) {
        const item = parseJwkObject(json[i] || {}, items.length + 1, seenKids);
        items.push(item);
        findings.push(...item.findings);
      }
    } else {
      throw new Error('JSON file does not contain a JWKS "keys" array or a JWK "kty" object.');
    }
  } else {
    // 3. JWT (one or more dot-separated tokens)
    const tokens = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && l.split('.').length === 3);
    if (!tokens.length) {
      throw new Error('Could not recognize JWT, JWKS/JWK JSON or X.509 PEM certificate content.');
    }
    format = tokens.length > 1 ? 'JWT Token List' : 'JSON Web Token (JWT)';
    for (let i = 0; i < tokens.length; i += 1) {
      const item = parseJwtToken(tokens[i], items.length + 1, nowMs, warnDays);
      items.push(item);
      findings.push(...item.findings);
    }
  }

  const kindCounts = {};
  for (const it of items) kindCounts[it.kind] = (kindCounts[it.kind] || 0) + 1;

  const errorCount = findings.filter((f) => f.severity === 'error').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const expiredCount = findings.filter((f) => f.category === 'Expiry' && f.severity === 'error').length;
  const privateKeyCount = findings.filter((f) => f.category === 'Private Key').length;

  return {
    fileName,
    format,
    items,
    findings,
    kindCounts,
    stats: {
      itemCount: items.length,
      errorCount,
      warningCount,
      expiredCount,
      privateKeyCount,
    },
  };
}

function buildSecurityAuditMarkdown(entries) {
  const lines = ['# JWT, JWKS & X.509 Security & Expiry Audit', ''];
  let totalItems = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const e of entries) {
    totalItems += e.parsed.stats.itemCount;
    totalErrors += e.parsed.stats.errorCount;
    totalWarnings += e.parsed.stats.warningCount;
  }
  lines.push(`- **Files scanned:** ${entries.length}`);
  lines.push(`- **Total tokens / keys / certs:** ${totalItems}`);
  lines.push(`- **Errors:** ${totalErrors}`);
  lines.push(`- **Warnings:** ${totalWarnings}`);
  lines.push('');
  lines.push('## Summary by File');
  lines.push('');
  lines.push('| File | Format | Items | Expired | Private Keys | Errors | Warnings |');
  lines.push('| --- | --- | ---: | ---: | ---: | ---: | ---: |');
  for (const e of entries) {
    const s = e.parsed.stats;
    lines.push(`| \`${e.fileName}\` | ${e.parsed.format} | ${s.itemCount} | ${s.expiredCount} | ${s.privateKeyCount} | ${s.errorCount} | ${s.warningCount} |`);
  }
  lines.push('');
  lines.push('## Security & Expiry Findings');
  lines.push('');
  let any = false;
  for (const e of entries) {
    if (!e.parsed.findings.length) continue;
    any = true;
    lines.push(`### ${e.fileName}`);
    lines.push('');
    for (const f of e.parsed.findings) {
      lines.push(`- **[${f.severity.toUpperCase()}] ${f.category}** (\`${f.item}\`): ${f.finding}`);
    }
    lines.push('');
  }
  if (!any) lines.push('All JWT, JWKS and X.509 checks passed without errors or warnings.');
  return lines.join('\n') + '\n';
}

function buildKeySetDiffMarkdown(leftName, leftParsed, rightName, rightParsed) {
  const lines = [`# Key Set & Certificate Diff: ${leftName} vs ${rightName}`, ''];
  lines.push(`- **${leftName}:** ${leftParsed.format}, ${leftParsed.stats.itemCount} item(s)`);
  lines.push(`- **${rightName}:** ${rightParsed.format}, ${rightParsed.stats.itemCount} item(s)`);
  lines.push('');

  const leftMap = new Map(leftParsed.items.map((x) => [`${x.kind}:${x.id}`, x]));
  const rightMap = new Map(rightParsed.items.map((x) => [`${x.kind}:${x.id}`, x]));
  const allKeys = [...new Set([...leftMap.keys(), ...rightMap.keys()])];

  lines.push('| Item | Status | Left Alg / Validity | Right Alg / Validity |');
  lines.push('| --- | --- | --- | --- |');
  for (const k of allKeys) {
    const l = leftMap.get(k);
    const r = rightMap.get(k);
    if (!l) {
      lines.push(`| \`${k}\` | Added | - | ${r.alg} / ${r.validity} |`);
    } else if (!r) {
      lines.push(`| \`${k}\` | Removed | ${l.alg} / ${l.validity} | - |`);
    } else {
      const same = l.alg === r.alg && l.validity === r.validity && l.use === r.use;
      lines.push(`| \`${k}\` | ${same ? 'Unchanged' : 'Changed'} | ${l.alg} / ${l.validity} | ${r.alg} / ${r.validity} |`);
    }
  }
  return lines.join('\n') + '\n';
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildComplianceCsv(parsed, sourceName) {
  const header = ['file', 'index', 'kind', 'id', 'algorithm', 'use', 'validity', 'status', 'errors', 'warnings'];
  const rows = [header.join(',')];
  for (const it of parsed.items) {
    rows.push([
      sourceName, it.index, it.kind, it.id, it.alg, it.use, it.validity, it.status, it.errorCount, it.warningCount,
    ].map(csvCell).join(','));
  }
  return rows.join('\n') + '\n';
}

function buildComplianceMarkdown(parsed, sourceName) {
  const lines = [`# Compliance Inventory: ${sourceName}`, ''];
  lines.push(`- **Format:** ${parsed.format}`);
  lines.push(`- **Items:** ${parsed.stats.itemCount}`);
  lines.push(`- **Errors:** ${parsed.stats.errorCount} · **Warnings:** ${parsed.stats.warningCount}`);
  lines.push('');
  lines.push('| # | Type | Identifier | Algorithm | Use | Validity | Status |');
  lines.push('| ---: | --- | --- | --- | --- | --- | --- |');
  for (const it of parsed.items) {
    lines.push(`| ${it.index} | ${it.kind} | \`${it.id}\` | \`${it.alg}\` | ${it.use} | ${it.validity} | ${it.status.toUpperCase()} |`);
  }
  return lines.join('\n') + '\n';
}

module.exports = {
  b64urlDecode,
  parseCryptoFile,
  buildSecurityAuditMarkdown,
  buildKeySetDiffMarkdown,
  buildComplianceCsv,
  buildComplianceMarkdown,
};
