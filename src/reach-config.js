'use strict';
module.exports = {
  prefix: 'zovoJwt',
  triesKey: 'zovoJwt.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditSecurity', title: 'Audit JWT, JWKS and X.509 security and expiry', command: 'zovoJwt.auditSecurity' },
    { id: 'diffKeySets', title: 'Compare two JWKS, JWT or certificate files', command: 'zovoJwt.diffKeySets' },
    { id: 'exportComplianceReport', title: 'Export CSV and Markdown compliance inventory', command: 'zovoJwt.exportComplianceReport' },
  ],
};
