# myjwt

**A HackIta tool** · [hackita.it](https://hackita.it)

`myjwt` decodes and audits a JSON Web Token from the terminal. It is a single Python file with no dependencies, and it never sends anything over the network.

* Decodes header and payload (JWS), and recognizes encrypted JWE tokens
* Converts `exp`, `nbf` and `iat` to readable UTC dates with relative time, including millisecond timestamps
* Lists potential issues to verify: `alg: none`, empty signatures, `kid`, `jku`, `x5u`, `jwk`, `x5c`, missing or inconsistent time claims, missing `iss`/`aud`, authorization-relevant claims
* Verifies an HMAC signature (HS256/384/512) with a secret or the exact bytes of a key file you provide (it does not search for secrets)
* Accepts the token raw, from stdin, from a file, or pasted with `Authorization: Bearer`, cookie syntax or quotes
* Optional JSON output for scripts

Decoding a token confirms nothing by itself: the labels tell you **what to test**, the target's behaviour tells you whether it is vulnerable.

## Install

```bash
git clone https://github.com/hack-ita/myjwt
cd myjwt
chmod +x myjwt.py
```

Requires Python 3.8 or newer.

## Usage

```bash
./myjwt.py "$JWT"                                  # decode and list potential issues
echo "Authorization: Bearer $JWT" | ./myjwt.py     # header, cookie and quotes are stripped
./myjwt.py -f token.txt                            # read the token from a file
./myjwt.py "$JWT" -k mysecret                      # verify an HMAC signature
./myjwt.py "$JWT" -K key.pem                       # use the exact bytes of a file as the key
./myjwt.py "$JWT" --json                           # machine-readable output
./myjwt.py --help                                  # all options
```

## Example

```text
JWT decoded - JWS (3 parts)

== Header ==
{
  "alg": "none",
  "typ": "JWT"
}

== Payload ==
{
  "sub": "admin"
}

== Signature ==
  (empty)

== Potential issues (decoding confirms nothing: verify against the target) ==
  [CANDIDATE] alg is 'none': unsecured token. An issue only if the server accepts it.
  [REVIEW   ] no 'exp': the token may never expire (depends on the token profile).
  [INFO     ] no 'iss': check whether the server enforces an issuer.
  [INFO     ] no 'aud': check whether the server enforces an audience (token substitution).
  [INFO     ] authorization-relevant claims: sub. Relevant only if signature checking can be bypassed.
```

| Label | Meaning |
| --- | --- |
| `CONFIRMED` | Proven by the tool itself |
| `CANDIDATE` | Worth testing first; only the target can confirm it |
| `REVIEW` | Depends on the application's rules |
| `INFO` | Context |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | OK |
| `1` | Invalid or unreadable token |
| `2` | Usage error |
| `3` | Signature does not match (`-k` / `-K`) |

See `--help` and the header of `myjwt.py` for the full list.

## Guide

The full methodology for testing JWTs (signature, keys, headers, claims, sessions) is in the HackIta guide: [hackita.it/articoli/jwt-attacks](https://en.hackita.it/articoli/jwt-attacks/).

## Legal

Use `myjwt` only on tokens and systems you own or are explicitly authorized to test: your own labs, CTF platforms such as Hack The Box, and contracted penetration tests.

## License

MIT © Canio Campaniello, [HackIta](https://hackita.it)
