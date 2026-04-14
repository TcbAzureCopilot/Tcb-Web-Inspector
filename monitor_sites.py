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
    """極致嚴謹：剝除所有代碼，只針對『肉眼可見純文字』進行指紋比對"""
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL|re.IGNORECASE)
    # 移除所有 HTML 標籤
    text_only = re.sub(r'<[^>]+>', ' ', html)
    # 將多個空白壓縮成單一空白
    return " ".join(text_only.split())

def get_ssl_expiry(url):
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
                remaining = cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()
                return f"{remaining.days}天"
    except Exception:
        return "N/A"

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
            
            # 純文字指紋計算
            clean_content = clean_html_for_fingerprint(res.text)
            curr_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:8]
            
            old_hash = old_state.get(site['name'], {}).get('hash')
            # 只有當舊資料存在且不同時，才判定為異動
            hash_changed = (old_hash is not None) and (curr_hash != old_hash)
            
            kw_ok = site['key'] in res.text
            ssl_info = get_ssl_expiry(site['url'])

            status = "🟢 正常"
            finger = f"✅ 穩定({curr_hash})"
            
            if not kw_ok or res.status_code != 200:
                status = "🔴 異常 (內容缺失)"
                is_critical = True
            elif hash_changed:
                status = "🟡 內容異動"
                finger = f"⚠️ 變動({old_hash}->{curr_hash})"

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            new_state[site['name']] = {"hash": curr_hash}
        except Exception as e:
            results.append({"name": site['name'], "url": site['url'], "status": "🔥 斷線", "ssl": "N/A", "latency": "0", "fingerprint": "N/A"})
            is_critical = True

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    return results, is_critical

# =====================================================================
# 儀表板更新與通報
# =====================================================================
def update_html(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "異常" in r['status'] or "斷線" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>\n"""

    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        
        import re
        # 🌟 關鍵修復：替換內容時，務必把錨點也寫回去，防止無限疊加
        pattern = r'.*?'
        replacement = f'\n{rows}'
        
        new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
        
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
    # 為了方便測試，暫時取消整點限制，每次都發 Teams。測試完可以改回 `if critical or datetime.now().minute < 15:`
    send_teams(data, critical)
