import requests
import ssl
import socket
import hashlib
import json
import os
import time
import re
from datetime import datetime

# =====================================================================
# 設定區
# =====================================================================
SITES = [
    {"name": "銀行官網", "url": "https://www.google.com", "key": "Google"},
    {"name": "合作金庫", "url": "https://www.tcb-bank.com.tw", "key": "合作金庫"},
    {"name": "台灣銀行", "url": "https://www.bot.com.tw", "key": "臺灣銀行"},
    {"name": "網路銀行", "url": "https://ebank.tcb-bank.com.tw", "key": "登入"},
]

STATE_FILE = "data/site_state.json"
DASHBOARD_FILE = "index.html"
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" 

# =====================================================================
# 深度檢測功能
# =====================================================================

def clean_html_for_fingerprint(html):
    """嚴謹化：剔除網頁中容易變動的隨機內容，避免誤報"""
    # 移除所有 Script 內容
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL)
    # 移除所有 Style 內容
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL)
    # 移除常見的動態 Token (如 CSRF, hidden inputs)
    html = re.sub(r'<input type="hidden".*?>', '', html)
    # 移除註解與空白
    html = re.sub(r'', '', html, flags=re.DOTALL)
    return "".join(html.split())

def get_ssl_expiry(url):
    """使用更強大的方式解析 SSL 效期"""
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(True)
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                # 取得剩餘天數
                remaining = cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()
                return f"{remaining.days}天"
    except Exception:
        return "檢測中"

def check_sites():
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    is_critical = False
    headers = {'User-Agent': 'Mozilla/5.0'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            
            # 指紋計算 (嚴謹版)
            clean_content = clean_html_for_fingerprint(res.text)
            curr_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:12]
            
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = old_hash and curr_hash != old_hash
            
            # 關鍵字檢查
            kw_ok = site['key'] in res.text
            ssl_info = get_ssl_expiry(site['url'])

            status = "🟢 正常"
            finger = "✅ 穩定"
            
            # 只有當「斷線」或「關鍵字消失」才發緊急告警
            if not kw_ok or res.status_code != 200:
                status = "🔴 異常 (內容缺失)"
                is_critical = True
            elif hash_changed:
                status = "🟡 內容異動"
                finger = f"⚠️ 變動({curr_hash})"

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            new_state[site['name']] = {"hash": curr_hash}
        except Exception:
            results.append({"name": site['name'], "url": site['url'], "status": "🔥 斷線", "ssl": "N/A", "latency": "0", "fingerprint": "N/A"})
            is_critical = True

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    return results, is_critical

# =====================================================================
# 3. 儀表板更新邏輯 (修正切分錯誤)
# =====================================================================
def update_html(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "異常" in r['status'] or "斷線" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>"""

    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        
        # 🌟 終極防彈版：使用正規表達式直接覆蓋，絕對不會有 empty separator 的問題
        import re
        
        # 尋找 到 之間的所有內容並替換
        pattern = r'.*?'
        replacement = f'\n<tbody id="table-body">\n{rows}\n</tbody>\n'
        
        # 執行表格替換
        new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
        
        # 執行時間替換
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_content = re.sub(r'LAST UPDATE: <span id="update-time">.*?</span>', 
                             f'LAST UPDATE: <span id="update-time">{update_time}</span>', new_content)

        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(new_content)

def send_teams(results, is_critical):
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: return
    title = "🚨 系統緊急告警" if is_critical else "✅ 網站運行日報"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    requests.post(webhook, json=payload)

if __name__ == "__main__":
    data, critical = check_sites()
    update_html(data)
    if critical or datetime.now().minute < 15:
        send_teams(data, critical)
