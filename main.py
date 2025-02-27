import re
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Carregar Token do Bot e ID do Telegram do arquivo de configuração
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Lista de IPs bloqueados
blocked_ips = set()

# Padrões de ataques comuns
SQL_INJECTION_PATTERNS = [r"union\s+select", r"drop\s+table", r"insert\s+into", r"delete\s+from", r"select\s+\*"]
XSS_PATTERNS = [r"<script>", r"javascript:", r"onerror=", r"onload="]
BOT_USER_AGENTS = ["bot", "crawl", "spider", "scanner", "wget", "curl"]

# Função para enviar alertas via Telegram
def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    requests.post(url, data=data)

@app.before_request
def security_layer():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '').lower()
    request_url = request.url.lower()

    # Bloqueio de IPs previamente detectados
    if ip in blocked_ips:
        return jsonify({"error": "Acesso negado por comportamento suspeito"}), 403

    # Proteção contra SQL Injection
    if any(re.search(pattern, request_url) for pattern in SQL_INJECTION_PATTERNS):
        blocked_ips.add(ip)
        send_telegram_alert(f"🚨 Tentativa de SQL Injection detectada! 🚨\nIP: {ip}\nURL: {request_url}")
        return jsonify({"error": "Acesso negado por tentativa de ataque SQL"}), 403

    # Proteção contra XSS (Cross-Site Scripting)
    if any(re.search(pattern, request_url) for pattern in XSS_PATTERNS):
        blocked_ips.add(ip)
        send_telegram_alert(f"🚨 Tentativa de ataque XSS detectada! 🚨\nIP: {ip}\nURL: {request_url}")
        return jsonify({"error": "Acesso negado por tentativa de ataque XSS"}), 403

    # Bloqueio de Bots e Scrapers
    if any(keyword in user_agent for keyword in BOT_USER_AGENTS):
        blocked_ips.add(ip)
        send_telegram_alert(f"🚨 Bot suspeito detectado e bloqueado! 🚨\nIP: {ip}\nUser-Agent: {user_agent}")
        return jsonify({"error": "Acesso negado para robôs não autorizados"}), 403

@app.route('/')
def home():
    return "🔥 Sistema de Segurança Buyzon Ativo!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
