#!/usr/bin/env python3
"""
myjwt - minimal JWT decoder and auditor for the terminal.
A HackIta tool - https://hackita.it - https://github.com/hack-ita/myjwt
Author: Canio Campaniello (HackIta). License: MIT.

Decodes header and payload, converts time claims, lists potential issues to
verify, and checks HMAC (HS256/384/512) signatures against a key you provide.
It never sends anything over the network. Python 3.8+, standard library only.

Use it only on tokens you are authorized to test (labs, CTFs, pentests).

Exit codes:
  0  OK (decoded; signature valid when -k/-K is used)
  1  invalid or unreadable token
  2  usage error
  3  signature does NOT match (-k / -K)
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

VERSION = "1.1"

HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

AUTHZ_CLAIMS = {
    "role", "roles", "admin", "is_admin", "isadmin", "isAdmin", "scope",
    "scopes", "scp", "permissions", "perms", "groups", "group", "uid",
    "user_id", "userid", "userId", "username", "user", "email", "sub",
    "tenant", "org", "account",
}

TIME_CLAIMS = ("iat", "nbf", "exp")
# '+' and '/' are kept so that standard-base64 mistakes get a clear error;
# '=' is not, so "jwt=eyJ..." (cookie) and "...==" padding are split off cleanly.
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/]+(?:\.[A-Za-z0-9_\-+/]*){1,4}")
B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]*$")


# ----------------------------------------------------------------- output --
class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t):
        return self._wrap("1", t)

    def dim(self, t):
        return self._wrap("2", t)

    def red(self, t):
        return self._wrap("31;1", t)

    def yellow(self, t):
        return self._wrap("33;1", t)

    def green(self, t):
        return self._wrap("32;1", t)

    def cyan(self, t):
        return self._wrap("36", t)


class JwtError(Exception):
    """Raised when the input cannot be parsed as a JWT."""


# --------------------------------------------------------------- decoding --
def extract_token(raw):
    """Pull a JWT-looking string out of raw text (header line, cookie, quotes)."""
    candidates = TOKEN_RE.findall(raw.strip())
    if not candidates:
        raise JwtError("no token found: a JWT looks like xxxxx.yyyyy.zzzzz")
    return max(candidates, key=len)


def b64url_decode(segment, label):
    if not B64URL_RE.match(segment):
        bad = sorted(set(re.findall(r"[^A-Za-z0-9_\-]", segment)))
        hint = ""
        if set(bad) & set("+/="):
            hint = " (standard base64 characters found; JWT uses base64url without padding)"
        raise JwtError(f"{label}: invalid base64url characters {bad}{hint}")
    if len(segment) % 4 == 1:
        raise JwtError(f"{label}: invalid base64url length ({len(segment)} chars)")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise JwtError(f"{label}: base64url decode failed ({exc})")


def parse_json_part(data, label, must_be_object):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise JwtError(f"{label}: not valid UTF-8")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        if must_be_object:
            raise JwtError(f"{label}: not valid JSON ({exc.msg} at char {exc.pos})")
        return None, text
    if must_be_object and not isinstance(obj, dict):
        raise JwtError(f"{label}: JSON is not an object")
    return obj, text


def parse_token(token):
    parts = token.split(".")
    if len(parts) == 5:
        header_raw = b64url_decode(parts[0], "header")
        header, _ = parse_json_part(header_raw, "header", True)
        return {"kind": "JWE", "parts": parts, "header": header}
    if len(parts) != 3:
        raise JwtError(f"expected 3 dot-separated parts (JWS) or 5 (JWE), found {len(parts)}")
    header_raw = b64url_decode(parts[0], "header")
    payload_raw = b64url_decode(parts[1], "payload")
    sig_raw = b64url_decode(parts[2], "signature")
    header, _ = parse_json_part(header_raw, "header", True)
    payload, payload_text = parse_json_part(payload_raw, "payload", False)
    return {
        "kind": "JWS",
        "parts": parts,
        "header": header,
        "payload": payload,
        "payload_text": payload_text,
        "payload_raw": payload_raw,
        "signature": sig_raw,
    }


# ------------------------------------------------------------------- time --
def humanize(seconds):
    seconds = int(abs(seconds))
    units = (("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1))
    out = []
    for suffix, size in units:
        if seconds >= size:
            out.append(f"{seconds // size}{suffix}")
            seconds %= size
        if len(out) == 2:
            break
    return " ".join(out) if out else "0s"


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def to_seconds(value):
    """Normalize a NumericDate to seconds. Returns (seconds, looks_like_ms)."""
    ts = float(value)
    if abs(ts) > 1e11:
        return ts / 1000.0, True
    return ts, False


def describe_time(claim, value, now):
    """Return (text, state) for a NumericDate claim."""
    if not is_number(value):
        return f"invalid (expected a number, got {type(value).__name__})", "bad"
    try:
        ts_s, is_ms = to_seconds(value)
        note = " [looks like milliseconds]" if is_ms else ""
        when = datetime.fromtimestamp(ts_s, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"out of range ({value})", "bad"
    stamp = when.strftime("%Y-%m-%d %H:%M:%S UTC")
    delta = ts_s - now
    if claim == "exp":
        if delta < 0:
            return f"{stamp}  (expired {humanize(delta)} ago){note}", "expired"
        return f"{stamp}  (expires in {humanize(delta)}){note}", "ok"
    if claim == "nbf":
        if delta > 0:
            return f"{stamp}  (not valid for another {humanize(delta)}){note}", "future"
        return f"{stamp}  (valid since {humanize(delta)} ago){note}", "ok"
    if delta > 0:
        return f"{stamp}  (in the future by {humanize(delta)}){note}", "future"
    return f"{stamp}  ({humanize(delta)} ago){note}", "ok"


# ----------------------------------------------------------- potential issues --
# Decoding a token cannot confirm a vulnerability: the server's behaviour does.
# Labels: CONFIRMED  proven by this tool (e.g. a verified signature)
#         CANDIDATE  worth testing first; only the target can confirm it
#         REVIEW     depends on the application's rules
#         INFO       context
def analyze(info, now):
    """Return a list of (label, message)."""
    findings = []
    header = info["header"]
    alg = header.get("alg")

    if info["kind"] == "JWE":
        findings.append(("INFO", "JWE (encrypted token): payload cannot be read without the key."))
        if isinstance(alg, str):
            findings.append(("INFO", f"key management alg: {alg}; content alg (enc): {header.get('enc')}"))
        return findings

    payload = info["payload"] if isinstance(info["payload"], dict) else {}
    sig = info["signature"]

    if alg is None:
        findings.append(("REVIEW", "header has no 'alg': check how the server picks the verification algorithm."))
    elif not isinstance(alg, str):
        findings.append(("REVIEW", f"'alg' is not a string ({alg!r}): unusual, check parser behaviour."))
    else:
        low = alg.lower()
        if low == "none":
            findings.append(("CANDIDATE", f"alg is '{alg}': unsecured token. An issue only if the server accepts it."))
            if alg != "none":
                findings.append(("INFO", "JOSE algorithm names are exact strings; other casings only matter "
                                         "for a legacy or case-insensitive parser/filter."))
        elif alg.upper() in HMAC_ALGS:
            findings.append(("INFO", f"{alg} is symmetric: its security rests entirely on the strength "
                                     "of the shared secret."))
        elif alg[:2].upper() in ("RS", "PS", "ES") or alg in ("EdDSA", "Ed25519", "Ed448"):
            findings.append(("INFO", f"{alg} is asymmetric: algorithm confusion applies only if the server "
                                     "also accepts HS* with that key (needs the public key)."))
        else:
            findings.append(("INFO", f"unrecognized alg '{alg}'."))

    if len(sig) == 0 and (not isinstance(alg, str) or alg.lower() != "none"):
        findings.append(("CANDIDATE", "signature is empty but alg is not 'none': check whether the server "
                                      "skips verification."))
    elif len(sig) > 0 and isinstance(alg, str) and alg.lower() == "none":
        findings.append(("REVIEW", "alg is 'none' but a signature is present: inconsistent token."))

    if "kid" in header:
        kid = header["kid"]
        findings.append(("REVIEW", f"'kid' present ({kid!r}): matters only if the server uses it to read a "
                                   "file or query a database."))
        if isinstance(kid, str) and re.search(r"(\.\./|\.\.\\|['\";]|\bunion\b|/dev/null)", kid, re.I):
            findings.append(("CANDIDATE", "'kid' contains traversal or injection characters: "
                                          "check whether the server processes it unsafely."))
    if "jku" in header:
        findings.append(("CANDIDATE", f"'jku' present ({header['jku']!r}): remote JWK Set URL. "
                                      "Check whether the server fetches it (host allow-list, SSRF)."))
    if "x5u" in header:
        findings.append(("CANDIDATE", f"'x5u' present ({header['x5u']!r}): remote certificate URL. "
                                      "Check whether the server fetches it (host allow-list, SSRF)."))
    if "jwk" in header:
        findings.append(("CANDIDATE", "'jwk' present: public key embedded in the token. "
                                      "Check that the server does not trust it."))
    if "x5c" in header:
        findings.append(("CANDIDATE", "'x5c' present: certificate chain embedded in the token. "
                                      "Check that the chain is validated against trusted roots."))
    if "crit" in header:
        findings.append(("INFO", f"'crit' header present ({header['crit']!r}): "
                                 "unknown critical parameters must be rejected."))

    if payload:
        if "exp" not in payload:
            findings.append(("REVIEW", "no 'exp': the token may never expire (depends on the token profile)."))
        for claim in ("exp", "nbf", "iat"):
            if claim in payload:
                _, state = describe_time(claim, payload[claim], now)
                if state == "bad":
                    findings.append(("REVIEW", f"'{claim}' is not a valid NumericDate."))
        if is_number(payload.get("exp")) and is_number(payload.get("iat")):
            try:
                exp_s, exp_ms = to_seconds(payload["exp"])
                iat_s, iat_ms = to_seconds(payload["iat"])
            except (OverflowError, ValueError):
                exp_s = iat_s = None
            if exp_s is not None:
                if exp_ms != iat_ms:
                    findings.append(("REVIEW", "'exp' and 'iat' use different units (seconds vs milliseconds)."))
                else:
                    life = exp_s - iat_s
                    if life > 86400:
                        findings.append(("REVIEW", f"long lifetime: exp - iat = {humanize(life)}."))
                    if life < 0:
                        findings.append(("REVIEW", "exp is earlier than iat."))
        if "exp" in payload and is_number(payload["exp"]):
            _, state = describe_time("exp", payload["exp"], now)
            if state == "expired":
                findings.append(("INFO", "token is expired: you can test whether the server still accepts it."))
        if "iss" not in payload:
            findings.append(("INFO", "no 'iss': check whether the server enforces an issuer."))
        if "aud" not in payload:
            findings.append(("INFO", "no 'aud': check whether the server enforces an audience "
                                     "(token substitution)."))
        hits = sorted(k for k in payload if k in AUTHZ_CLAIMS)
        if hits:
            findings.append(("INFO", f"authorization-relevant claims: {', '.join(hits)}. "
                                     "Relevant only if signature checking can be bypassed."))
    return findings


# ------------------------------------------------------------- HMAC tools --
def hmac_digest(alg, secret, signing_input):
    return hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()


def signing_input(info):
    return (info["parts"][0] + "." + info["parts"][1]).encode("ascii")


def require_hmac(info):
    if info["kind"] != "JWS":
        raise JwtError("HMAC operations need a signed token (JWS), not a JWE")
    alg = info["header"].get("alg")
    if not isinstance(alg, str) or alg.upper() not in HMAC_ALGS:
        raise JwtError(f"alg is {alg!r}: only HS256, HS384 and HS512 are supported")
    return alg.upper()


def verify_secret(info, secret):
    """secret is bytes: exact key material (e.g. a PEM file, newline included)."""
    alg = require_hmac(info)
    expected = hmac_digest(alg, secret, signing_input(info))
    return hmac.compare_digest(expected, info["signature"])


# --------------------------------------------------------------- rendering --
def pretty(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


def render(info, findings, st, now, show_signature=True):
    out = []
    kind = "JWE (5 parts)" if info["kind"] == "JWE" else "JWS (3 parts)"
    out.append(st.bold(f"JWT decoded - {kind}"))
    out.append("")
    out.append(st.cyan("== Header =="))
    out.append(pretty(info["header"]))
    out.append("")

    if info["kind"] == "JWE":
        out.append(st.dim("Payload is encrypted and cannot be decoded without the key."))
    else:
        out.append(st.cyan("== Payload =="))
        if info["payload"] is not None:
            out.append(pretty(info["payload"]))
        else:
            out.append("(not JSON) " + info["payload_text"])
        out.append("")
        if isinstance(info["payload"], dict):
            lines = []
            for claim in TIME_CLAIMS:
                if claim in info["payload"]:
                    text, state = describe_time(claim, info["payload"][claim], now)
                    color = {"ok": st.green, "expired": st.red, "future": st.yellow, "bad": st.red}[state]
                    lines.append(f"  {claim:<4} {color(text)}")
            if lines:
                out.append(st.cyan("== Time claims =="))
                out.extend(lines)
                out.append("")
        if show_signature:
            sig = info["signature"]
            out.append(st.cyan("== Signature =="))
            if sig:
                out.append(f"  {len(sig)} bytes: {sig.hex()}")
            else:
                out.append("  (empty)")
            out.append("")

    out.append(st.cyan("== Potential issues (decoding confirms nothing: verify against the target) =="))
    if not findings:
        out.append("  none")
    colors = {"CONFIRMED": st.red, "CANDIDATE": st.yellow, "REVIEW": st.cyan, "INFO": st.dim}
    order = {"CONFIRMED": 0, "CANDIDATE": 1, "REVIEW": 2, "INFO": 3}
    for sev, msg in sorted(findings, key=lambda f: order[f[0]]):
        out.append(f"  [{colors[sev](sev.ljust(9))}] {msg}")
    return "\n".join(out)


# --------------------------------------------------------------------- CLI --
def build_parser():
    p = argparse.ArgumentParser(
        prog="myjwt",
        description="myjwt by HackIta: decode and audit a JWT from the terminal. Offline only.",
        epilog="Examples:\n"
               "  myjwt eyJhbGciOi...\n"
               "  echo 'Authorization: Bearer eyJ...' | myjwt\n"
               "  myjwt TOKEN -k mysecret            verify an HMAC signature\n"
               "  myjwt TOKEN -K key.pem             verify using the exact bytes of a file\n"
               "  myjwt TOKEN --json                 machine-readable output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("token", nargs="?", help="JWT, or '-' / nothing to read from stdin")
    p.add_argument("-f", "--file", help="read the token from a file")
    p.add_argument("-k", "--secret", help="verify the HMAC signature with this secret")
    p.add_argument("-K", "--secret-file",
                   help="verify the HMAC signature using the exact bytes of a file as key "
                        "(e.g. a PEM public key, for algorithm-confusion tests)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"myjwt {VERSION} - a HackIta tool (hackita.it)")
    return p


def read_input(args):
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            raise JwtError(f"cannot read file: {exc.strerror}")
    if args.token and args.token != "-":
        return args.token
    if sys.stdin.isatty():
        return None
    return sys.stdin.read()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    st = Style(color)
    now = time.time()

    try:
        raw = read_input(args)
        if raw is None:
            parser.print_usage(sys.stderr)
            print("myjwt: error: no token given", file=sys.stderr)
            return 2
        token = extract_token(raw)
        info = parse_token(token)
    except JwtError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    findings = analyze(info, now)
    exit_code = 0
    result = {}

    try:
        if args.secret is not None or args.secret_file:
            if args.secret_file:
                try:
                    with open(args.secret_file, "rb") as fh:
                        key, label = fh.read(), f"file {args.secret_file}"
                except OSError as exc:
                    raise JwtError(f"cannot read key file: {exc.strerror}")
            else:
                key, label = args.secret.encode("utf-8"), repr(args.secret)
            ok = verify_secret(info, key)
            result["verify"] = {"key": label, "valid": ok}
            if ok:
                findings.append(("CONFIRMED", f"signature verified with key {label}."))
            else:
                exit_code = 3
    except JwtError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = info.get("payload")
        doc = {
            "type": info["kind"],
            "header": info["header"],
            "payload": payload if payload is not None else info.get("payload_text"),
            "signature_hex": info["signature"].hex() if "signature" in info else None,
            "potential_issues": [{"label": s, "message": m} for s, m in findings],
        }
        doc.update(result)
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return exit_code

    print(render(info, findings, st, now))

    if "verify" in result:
        print()
        print(st.cyan("== Verification =="))
        key_label = result["verify"]["key"]
        if result["verify"]["valid"]:
            print("  " + st.green(f"Signature VALID with key {key_label}"))
        else:
            print("  " + st.red(f"Signature does NOT match key {key_label}"))
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
