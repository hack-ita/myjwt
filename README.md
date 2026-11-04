# myjwt

**JWT Security Testing Framework** · a [HackIta](https://hackita.it) tool

`myjwt` is a single-file Python command-line tool to decode, inspect and audit JSON Web Tokens (JWT). It is built for authorized security assessments, CTFs and lab work, and for developers who want to check how their own tokens are configured.

* Decodes the header and payload of JWS tokens and recognizes encrypted JWE tokens
* Audits a token and ranks the findings by severity, with an overall risk score
* Verifies HMAC (HS256/384/512), RSA (RS/PS), ECDSA (ES) and EdDSA signatures
* Inspects a JWKS endpoint and warns when private key material is exposed
* Detects serialized or compressed data hidden inside payload claims
* Output in six languages: English, Italian, Spanish, Portuguese, German and French
* Works offline for decoding, auditing and verification. Network access only happens when you explicitly pass a URL option.

> Decoding a token proves nothing by itself. A finding tells you **what to test**; only the behaviour of the target tells you whether it is really vulnerable.

## Table of contents

* [Install](#install)
* [Requirements](#requirements)
* [Quick start](#quick-start)
* [Input methods](#input-methods)
* [Options](#options)
* [What the audit checks](#what-the-audit-checks)
* [Risk score](#risk-score)
* [Nested payload analyzer](#nested-payload-analyzer)
* [JWKS analysis](#jwks-analysis)
* [Languages](#languages)
* [Exit codes](#exit-codes)
* [Known limitations](#known-limitations)
* [Defensive checklist](#defensive-checklist)
* [Guides](#guides)
* [Legal](#legal)
* [License](#license)

## Install

```bash
git clone https://github.com/hack-ita/myjwt
cd myjwt
chmod +x myjwt.py
./myjwt.py --help
```

## Requirements

| Feature | Needs |
| --- | --- |
| Decode, audit, HMAC verification, wordlist check | Python 3.8 or newer, standard library only |
| Asymmetric verification (`-K`: RSA, ECDSA, EdDSA) | `pip install cryptography` |
| HTTP testing (`--url`, `--verify-endpoint`) | `pip install requests` |
| JWKS analysis (`--jwks`) | standard library only |

## Quick start

All examples use a sample token signed with the secret `secret`:

```bash
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDQyIiwibmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MTc2NzIyOTIwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUudGVzdCIsImF1ZCI6ImFwaSJ9.CGYSmszPlxLVdNdVPCSNz5u1tafyl4ILLix4JXqZRjs'
```

Decode a token:

```bash
./myjwt.py "$TOKEN"
```

```text
[*] TOKEN TYPE: JWS
[*] HEADER
{
  "alg": "HS256",
  "typ": "JWT"
}
[*] PAYLOAD
{
  "sub": "1042",
  "name": "alice",
  "role": "user",
  "iat": 1767225600,
  "exp": 1767229200,
  "iss": "https://auth.example.test",
  "aud": "api"
}
```

Audit it:

```bash
./myjwt.py --analyze "$TOKEN"
```

Verify an HMAC signature with a known secret:

```bash
./myjwt.py -k secret "$TOKEN"
```

```text
[*] VERIFICATION
[+] Signature VALID
```

Verify a signature with a public key (PEM):

```bash
./myjwt.py -K public.pem "$TOKEN"
```

Read the token from a file and print machine-readable findings:

```bash
./myjwt.py -f token.txt --analyze --json
```

## Input methods

| Method | Example |
| --- | --- |
| Argument | `./myjwt.py "$TOKEN"` |
| File | `./myjwt.py -f token.txt` |
| Standard input | `echo "$TOKEN" \| ./myjwt.py -f /dev/stdin` |

The tool extracts the token from surrounding text, so you can paste a full `Authorization: Bearer ...` header, a `Cookie:` line or a quoted value. If several candidates are present, the longest one is used.

Standard input is read through `-f /dev/stdin`. Piping into the command without `-f` prints the help and exits with code `2`.

## Options

| Option | Description |
| --- | --- |
| `token` | JWT to analyze (positional argument) |
| `-f`, `--file FILE` | Read the token from a file |
| `--analyze` | Run the vulnerability scanner and print the risk score |
| `-k`, `--secret SECRET` | HMAC secret, used to verify the signature |
| `-K`, `--pubkey FILE` | Public key file (PEM) for asymmetric verification |
| `--json` | Print the findings as JSON (works together with `--analyze`) |
| `--jwks URL` | Fetch and analyze a JWKS endpoint |
| `--insecure` | Disable TLS certificate verification for `--jwks` and HTTP testing |
| `--crack WORDLIST` | Check an HMAC token against a wordlist, to test secret strength |
| `--max-lines N` | Limit the number of wordlist lines read |
| `--attack {none,confusion,kid,forge}` | Generate a modified test token to try against a system you are authorized to test |
| `--generate ALG` | Build a fresh token from scratch, no input token needed (`none` or `HS256`/`HS384`/`HS512`) |
| `--exp SECONDS` | With `--generate`: expiry in seconds from now |
| `--set CLAIM=VALUE` | Claim to set in the modified or generated token (repeatable, the value can be JSON) |
| `--jku URL`, `--x5u URL` | Header URL to set in the modified token |
| `--url URL` | Target URL for HTTP testing |
| `--verify-endpoint URL` | Endpoint to send the modified token to (takes priority over `--url`) |
| `--method METHOD` | HTTP method, default `GET` |
| `--headers HEADERS` | Extra request headers, comma-separated (`Name: value,Name: value`) |
| `--success-strings LIST`, `--failure-strings LIST` | Comma-separated strings that mark success or failure in the response |
| `--poc` | Print a ready-to-run `curl` command (needs `--url`) |
| `--export-burp FILE` | Write a raw HTTP request file for Burp Repeater (needs `--url` and an attack) |
| `--no-color` | Disable ANSI colors (colors are also disabled when output is not a terminal) |
| `-en` `-it` `-es` `-pt` `-de` `-fr` | Output language |

Run `./myjwt.py --help` for the authoritative list.

## What the audit checks

`--analyze` classifies each finding as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`.

| Severity | Findings |
| --- | --- |
| `CRITICAL` | `alg` is `none` (unsecured token). ECDSA signature with a zeroed `r` or `s` value (CVE-2022-21449 pattern) |
| `HIGH` | Missing `alg`. Non-numeric `exp`. `kid` containing path traversal or SQL-like content. `jku` or `x5u` that is not HTTPS. Embedded `jwk` or `x5c` in the header |
| `MEDIUM` | Missing `typ`. `crit` header present. `b64` set to `false` (RFC 7797). Missing `exp`. `iat` in the future. `jku` or `x5u` present. `kid` with shell-like characters |
| `LOW` | Unexpected `typ`. Lifetime longer than 24 hours. Missing `iss`. Missing `aud` |
| `INFO` | Symmetric or asymmetric algorithm in use. Expired token. Claim names that look sensitive (`password`, `secret`, `token`, `api_key`, `email`) |

Each finding is a lead to verify against the target, not a confirmed vulnerability.

## Risk score

Each finding adds points, and the total sets the overall level.

| Severity | Points |
| --- | --- |
| `CRITICAL` | 10 |
| `HIGH` | 5 |
| `MEDIUM` | 2 |
| `LOW` | 1 |
| `INFO` | 0 |

| Total | Level |
| --- | --- |
| 15 or more | `CRITICAL` |
| 8 to 14 | `HIGH` |
| 3 to 7 | `MEDIUM` |
| 0 to 2 | `LOW` |

Example on a token whose `kid` points outside the key directory and which has no `exp`, `iss` or `aud`:

```text
[*] VULNERABILITY ANALYSIS
  [HIGH] Potential 'kid' path traversal
  [MEDIUM] Missing 'exp' (expiration) claim
  [LOW] Missing 'iss' (issuer) claim
  [LOW] Missing 'aud' (audience) claim
  [INFO] Symmetric HMAC (HS256) - secret strength is crucial

[*] Overall Risk Score: 9 (HIGH)
```

## Nested payload analyzer

Some applications store encoded objects inside a claim. For every string claim of 20 characters or more that decodes as Base64, `myjwt` tries to identify the content:

* GZIP and ZLIB compressed data (it decompresses and keeps analyzing)
* Java serialization
* PHP serialization
* Python pickle
* .NET ViewState
* anything else: a hex dump of the first 64 bytes

Serialized objects in a token are a good place to look for insecure deserialization.

## JWKS analysis

```bash
./myjwt.py --jwks https://example.com/.well-known/jwks.json
```

The tool downloads the key set, prints `kty`, `kid`, `alg` and `use` for every key, and additionally flags:

* A key containing the private parameter `d` — private key material is public
* Two keys sharing the same `kid` — a key confusion risk
* A key with no `kid` or no `use`
* A `use` that contradicts its `alg` (`use: sig` with an encryption algorithm, or the reverse)

## Generating test tokens

`--generate` builds a brand new token without needing an existing one, for lab setups and quick tests. It supports `alg none` and the HMAC algorithms:

```bash
./myjwt.py --generate HS256 -k secret --set sub=1042 --set role=admin --exp 3600
./myjwt.py --generate none --set sub=1042
```

## Verifying an x5c certificate chain

When the header carries an embedded `x5c` certificate chain, `--analyze` automatically checks the signature against the leaf certificate's public key and reports whether they match. This only proves the header is internally consistent — an attacker who controls the header can embed their own self-signed certificate, so a match is not proof the token is trustworthy.

## Exporting to Burp

`--export-burp FILE` writes a raw HTTP request (method, path, headers and the forged `Authorization: Bearer` header) built from `--url`, `--method` and `--headers`, ready to paste into Burp Repeater:

```bash
./myjwt.py "$TOKEN" --attack forge -k secret --set role=admin --url https://target.test/api/me --export-burp request.txt
```

## Languages

Add one language flag to translate the interface and the findings.

| Flag | Language | Guide |
| --- | --- | --- |
| `-en` (default) | English | [en.hackita.it/articoli/jwt](https://en.hackita.it/articoli/jwt/) |
| `-it` | Italiano | [hackita.it/articoli/jwt](https://hackita.it/articoli/jwt/) |
| `-es` | Español | [es.hackita.it/articoli/jwt](https://es.hackita.it/articoli/jwt/) |
| `-pt` | Português | [pt.hackita.it/articoli/jwt](https://pt.hackita.it/articoli/jwt/) |
| `-de` | Deutsch | [de.hackita.it/articoli/jwt](https://de.hackita.it/articoli/jwt/) |
| `-fr` | Français | [fr.hackita.it/articoli/jwt](https://fr.hackita.it/articoli/jwt/) |

Example:

```bash
./myjwt.py -it --analyze "$TOKEN"
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Invalid or unreadable token, or an operation failed |
| `2` | No input given (help is printed) or invalid arguments |
| `3` | The signature does not match (`-k` or `-K`) |
| `4` | A secret was found in the wordlist (`--crack`) |
| `130` | Interrupted with Ctrl+C |

Exit codes make the tool easy to use in scripts and CI jobs.

`--crack` also prints the attempt rate and, when it can estimate the wordlist size from the file, an ETA at that rate.

## Known limitations

* `--generate` only builds `alg none` and HMAC tokens; it has no private key to sign RSA/ECDSA/EdDSA tokens with. Use `--attack forge` on an existing HMAC token, or sign RSA/EC tokens with your own tooling.
* The nested payload analyzer can print a hex dump for long plain strings, such as URLs, that happen to decode as Base64. Treat a dump of unknown type as noise unless the claim really holds encoded data.
* `--json` prints findings only together with `--analyze`.
* `--analyze` and the signature checks work on JWS tokens. JWE tokens are only recognized and their header is shown, because the payload is encrypted.
* Asymmetric verification expects a public key in PEM format.
* A single `CRITICAL` finding gives a score of 10, so the overall level is `HIGH`; `CRITICAL` needs a total of 15 or more.

## Defensive checklist

If you maintain an application that issues or accepts JWTs, these are the points the audit looks at:

* Pin the accepted algorithms on the server and reject `none`
* Never let the token choose its own verification key: ignore embedded `jwk` and `x5c`, and allow-list any `jku` or `x5u` URL
* Treat `kid` as untrusted input and never use it to build file paths or SQL queries
* Use long, random secrets for HMAC, and keep asymmetric private keys out of any JWKS
* Always set `exp`, keep lifetimes short, and validate `iss` and `aud`
* Keep your JWT library updated, for example against the ECDSA flaw tracked as CVE-2022-21449
* Do not put secrets or serialized objects in token claims

## Guides

The full methodology for testing and securing JWTs is in the HackIta guide, available in six languages: [English](https://en.hackita.it/articoli/jwt/), [Italiano](https://hackita.it/articoli/jwt/), [Español](https://es.hackita.it/articoli/jwt/), [Português](https://pt.hackita.it/articoli/jwt/), [Deutsch](https://de.hackita.it/articoli/jwt/), [Français](https://fr.hackita.it/articoli/jwt/).

## Legal

Use `myjwt` only on tokens and systems you own or are explicitly authorized to test: your own labs, CTF platforms such as Hack The Box, and contracted penetration tests. You are responsible for how you use it.

## License

MIT © Canio Campaniello, [HackIta](https://hackita.it)
