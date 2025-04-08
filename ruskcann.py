#!/usr/bin/env python3
import os
import requests
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from fpdf import FPDF
import openai  # API real da OpenAI

# Configurações
OPENAI_API_KEY = "SUA_CHAVE_DA_OPENAI"  # 🔑 Obtenha em: https://platform.openai.com/
THREADS = 20
DOWNLOAD_PATH = os.path.expanduser("~/Downloads")

# Estilo do PDF
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'RELATÓRIO DE SEGURANÇA - RUSKSCAN AI', 0, 1, 'C')
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')

def generate_ai_analysis(vulnerability):
    """Usa GPT-4 para análise técnica real"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Você é um especialista em segurança cibernética."},
                {"role": "user", "content": f"""
                Explique em termos técnicos e comerciais esta vulnerabilidade:
                Nome: {vulnerability['name']}
                Local: {vulnerability['location']}
                Severidade: {vulnerability['severity']}/10
                Descrição: {vulnerability['description']}

                Inclua:
                1. Risco real em linguagem corporativa
                2. 3 recomendações técnicas
                3. Impacto financeiro potencial
                """}
            ]
        )
        return response.choices[0].message['content']
    except Exception as e:
        return f"Análise indisponível. Erro: {str(e)}"

def create_pdf_report(vulnerabilities, domain):
    """Gera PDF profissional"""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    # Título dinâmico baseado na urgência
    max_severity = max(vuln['severity'] for vuln in vulnerabilities)
    if max_severity >= 9:
        report_type = "CRITICO"
    elif max_severity >= 7:
        report_type = "ALTO-RISCO"
    else:
        report_type = "ANALITICO"

    filename = f"{report_type}-Relatorio-{domain}.pdf"
    filepath = os.path.join(DOWNLOAD_PATH, filename)

    # Cabeçalho
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'Relatório de Vulnerabilidades - {domain}', ln=1)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=1)
    pdf.ln(10)

    # Resumo executivo (gerado por IA)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Resumo Executivo', ln=1)
    pdf.set_font('Arial', '', 10)
    summary = generate_ai_analysis({
        "name": "Resumo Geral",
        "location": domain,
        "severity": max_severity,
        "description": f"Análise consolidada de {len(vulnerabilities)} vulnerabilidades"
    })
    pdf.multi_cell(0, 5, summary)
    pdf.ln(5)

    # Detalhes por vulnerabilidade
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Vulnerabilidades Detalhadas', ln=1)
    
    for vuln in vulnerabilities:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, f"{vuln['name']} (Severidade: {vuln['severity']}/10)", ln=1)
        
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 5, f"Local: {vuln['location']}", ln=1)
        
        analysis = generate_ai_analysis(vuln)
        pdf.multi_cell(0, 5, analysis)
        pdf.ln(3)
    
    # Salva o PDF
    pdf.output(filepath)
    return filepath

def scan_website(target):
    """Função de escaneamento simulada (substitua pelo scanner real)"""
    return [
        {
            "name": "SQL Injection",
            "severity": 9,
            "location": f"{target}/login.php?id=1'",
            "description": "Parâmetro vulnerável a injeção SQL clássica"
        },
        {
            "name": "XSS Armazenado",
            "severity": 8,
            "location": f"{target}/comments",
            "description": "Campo de comentários aceita scripts persistentes"
        }
    ]

def main():
    openai.api_key = OPENAI_API_KEY  # Configura API real
    
    target = input("Digite o domínio alvo (ex: google.com): ").strip()
    
    print("\n[+] Escaneando alvo...")
    vulnerabilities = scan_website(target)
    
    print("[+] Gerando relatório PDF profissional...")
    pdf_path = create_pdf_report(vulnerabilities, target)
    
    print(f"\n[✓] Relatório salvo em: {pdf_path}")
    print("Pronto para envio imediato!")

if __name__ == "__main__":
    main()
