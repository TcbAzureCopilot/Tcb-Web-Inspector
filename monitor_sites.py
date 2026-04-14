import requests
import ssl
import socket
import hashlib
import json
import os
import time
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
# 深度檢測：強化 SSL 抓取
# =====================================================================
def get_ssl_expiry(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        # 🌟 修正點：使用不驗證模式來強行抓取憑證內容
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = ssl.DER_cert_to_PEM_cert(cert)
                # 使用簡單路徑抓取有效期限
                from cryptography import x509 as crypto_x509
                cert_obj = crypto_x509.load_pem_x509_certificate(x509.encode())
                expiry_date = cert_obj.not_valid_after_utc
                days_left = (expiry_date.replace(tzinfo=None) - datetime.utcnow()).days
                return f"{days_left}天"
    except Exception as e:
        print(f"SSL Error for {url}: {e}")
        return "無法取得"

# 如果環境沒有 cryptography 套件，補救方案：
def get_ssl_expiry_backup(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert: return "N/A"
                expiry_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %G')
                days_left = (expiry_date - datetime.now()).days
                return f"{days_left}天"
    except: return "N/A"

def check_sites():
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    has_error = False
    headers = {'User-Agent': 'Mozilla/5.0'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            content = res.text
            
            kw_ok = site['key'] in content
            curr_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:10]
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = old_hash and curr_hash != old_hash
            
            # 優先使用第一種 SSL 抓取法
            ssl_info = get_ssl_expiry_backup(site['url'])

            status = "🟢 正常"
            finger = "✅ 未變動"
            if hash_changed: 
                status = "🚨 竄改預警"; finger = f"⚠️ 已變更"; has_error = True
            elif not kw_ok: 
                status = "🟡 內容異常"; has_error = True
            elif res.status_code != 200: 
                status = f"🔴 錯誤({res.status_code})"; has_error = True

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            new_state[site['name']] = {"hash": curr_hash}
        except Exception as e:
            results.append({"name": site['name'], "url": site['url'], "status": "🔥 斷線", "ssl": "N/A", "latency": "0", "fingerprint": "N/A"})
            has_error = True

    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    return results, has_error

# =====================================================================
# 3. 儀表板更新 (修正插入邏輯)
# =====================================================================
def update_html(results):
    table_rows = ""
    for r in results:
        style = "status-green"
        if "正常" not in r['status']: style = "status-red"
        
        table_rows += f"""
        <tr>
            <td>{r['name']}</td>
            <td><span class="status-badge {style}">{r['status']}</span></td>
            <td>{r['ssl']}</td>
            <td>{r['latency']}</td>
            <td><code>{r['fingerprint']}</code></td>
            <td><a href="{r['url']}" target="_blank">造訪網頁</a></td>
        </tr>"""

    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        
        # 🌟 修正點：使用更穩定的取代方式
        import re
        # 取代表格內容
        pattern = r'<tbody>.*?</tbody>'
        new_content = re.sub(pattern, f'<tbody id="table-body">{table_rows}</tbody>', content, flags=re.DOTALL)
        
        # 更新時間
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_content = re.sub(r'LAST UPDATE: <span id="update-time">.*?</span>', 
                             f'LAST UPDATE: <span id="update-time">{update_time}</span>', new_content)

        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(new_content)

def send_teams(results, is_urgent):
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: return
    title = "🚨 監控異常告警" if is_urgent else "✅ 監控整點報時"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
    
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    requests.post(webhook, json=payload)

if __name__ == "__main__":
    data, error = check_sites()
    update_html(data)
    if error or datetime.now().minute < 15:
        send_teams(data, error)
