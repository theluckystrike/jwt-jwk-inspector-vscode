# Changelog

## 0.1.0

- First release: `.jwt`, `.jwks`, `.jwk`, `.pem`, `.crt` and `.cer` files in a read-only visual inspector, decoded locally with Node crypto and plain JavaScript.
- Decodes JWT headers, payloads, expiry and `alg: none` / weak `HS256` warnings; JWKS/JWK key sets (`kid`, `kty`, `use`, `alg`, private-key flags); and X.509 PEM certificate metadata (subject, issuer, SANs, validity dates, expired and self-signed flags).
- Zovo Pro tools with 1 free try each: offline security and expiry Markdown audit report, two-file JWKS/JWT/certificate Markdown diff, and CSV and Markdown compliance inventory export. Get Zovo Pro first shows what Pro includes and the tries left, in an editor tab.
