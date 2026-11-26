# JWT, JWKS & X.509 Cert Inspector for VS Code

Open JWT tokens, JWKS key sets and X.509 PEM certificates in the editor. Pasting production tokens, signing keys or TLS certificates into online decoders exposes credentials outside your machine. Reading base64 strings or PEM blocks as plain text hides weak algorithms, expired certificates and private key leaks. This extension decodes `.jwt`, `.jwks`, `.jwk`, `.pem`, `.crt` and `.cer` files locally with built-in Node crypto and plain JavaScript, without an external binary or data upload.

![JWT, JWKS & X.509 Cert Inspector showing decoded keys, algorithms, expiry status and security findings](images/screenshot.png)

## What it opens

- JSON Web Tokens (`.jwt`) with header, payload claims, algorithm and expiry decoding.
- JSON Web Key Sets and single keys (`.jwks`, `.jwk`) with `kid`, `kty`, `use`, `alg` and key parameters.
- X.509 PEM certificates and bundles (`.pem`, `.crt`, `.cer`) with subject, issuer, SANs, validity dates and self-signed checks.
- Nothing to install, nothing uploaded.

## The free part

- Items inventory table: lists every token, JWK entry or X.509 certificate in the file with type, identifier (`kid` or subject), algorithm, validity window and risk status.
- Claims & Metadata tab: displays decoded JWT claims, JWK fields and X.509 SANs, serial numbers and SHA-256 fingerprints offline.
- Security Findings tab: flags `alg: none`, weak `HS256` tokens, missing `exp` claims, expired or soon-to-expire certificates, self-signed certificates, duplicate `kid` values and embedded private key material.
- Search and filter: filter entries by text, type or risk status offline.

## The Pro tools, with 1 free try

Pro adds the audit, comparison and export steps: run an offline Markdown security and expiry audit across one file or a workspace folder, compare two JWKS, JWT or certificate files in Markdown, or export a non-destructive CSV and Markdown compliance inventory locally. Your first try of each Pro tool is free. Zovo Pro is USD 19 once, and the team licence is USD 59.

## Why not web decoders

Production JWTs carry session claims, JWKS files hold identity-provider signing keys and PEM bundles can include private keys. Sending them to a third-party website violates security policy. A local inspector decodes tokens, key sets and X.509 certificates directly inside VS Code, offline.

## More tools by Zovo

See full docs and install options at [vscode.zovo.one/extensions/zovo-jwt-jwk-inspector/](https://vscode.zovo.one/extensions/zovo-jwt-jwk-inspector/), browse all Zovo VS Code extensions at [vscode.zovo.one](https://vscode.zovo.one/), or explore [Zovo Pro](https://vscode.zovo.one/pro/).
