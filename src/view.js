'use strict';
// View model for JWT, JWKS & X.509 Cert Inspector: pagination, search/filter and findings.

class CryptoViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', kind: '', status: '' };
    this.filtered = parsed.items.slice();
  }

  summary() {
    const s = this.parsed.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      format: this.parsed.format,
      itemCount: s.itemCount,
      errorCount: s.errorCount,
      warningCount: s.warningCount,
      expiredCount: s.expiredCount,
      privateKeyCount: s.privateKeyCount,
      kinds: Object.entries(this.parsed.kindCounts).sort((a, b) => b[1] - a[1]),
      metaRows: this.parsed.items.flatMap((it) => Object.entries(it.meta).map(([k, v]) => ({ item: it.id, key: k, value: String(v) }))).slice(0, 400),
      findings: this.parsed.findings.slice(0, 300),
    };
  }

  totalCount() {
    return this.parsed.items.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const kind = f && typeof f.kind === 'string' ? f.kind.trim() : '';
    const status = f && typeof f.status === 'string' ? f.status.trim() : '';
    this.filter = { text, kind, status };
    this.filtered = this.parsed.items.filter((it) => {
      if (kind && it.kind !== kind) return false;
      if (status === 'error' && it.status !== 'error') return false;
      if (status === 'warning' && it.status !== 'warning') return false;
      if (status === 'ok' && it.status !== 'ok') return false;
      if (text) {
        const hay = `${it.kind} ${it.id} ${it.label} ${it.alg} ${it.use} ${it.validity}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((it) => ({
      index: it.index,
      kind: it.kind,
      id: it.id,
      alg: it.alg,
      use: it.use,
      validity: it.validity,
      status: it.status,
      errorCount: it.errorCount,
      warningCount: it.warningCount,
    }));
  }

  detail(index) {
    const it = this.parsed.items.find((x) => x.index === index) || this.parsed.items[0] || null;
    if (!it) return null;
    return {
      index: it.index,
      kind: it.kind,
      id: it.id,
      label: it.label,
      alg: it.alg,
      use: it.use,
      validity: it.validity,
      status: it.status,
      meta: it.meta,
      findings: it.findings,
      raw: it.raw,
    };
  }
}

module.exports = { CryptoViewModel };
