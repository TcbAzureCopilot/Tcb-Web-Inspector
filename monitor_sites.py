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
# 1. 監控設定區 (可自行增減網站)
# =====================================================================
SITES = [
    {"name": "銀行官網", "url": "https://www.google.com", "key": "Google"},
    {"name": "合作金庫", "url": "https://www.tcb-bank.com.tw", "key": "合作金庫"},
    {"name": "台灣銀行", "url": "https://www.bot.com.tw", "key": "臺灣銀行"},
    {"name": "網路銀行", "url": "https://ebank.tcb-bank.com.tw", "key": "登入"},
]

# 檔案路徑與網址設定
STATE_FILE = "data/site_state.json"
DASHBOARD_FILE = "index.html"
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" 

# =====================================================================
# 2. 深度檢測功能 (指紋與 SSL)
# =====================================================================

def clean_html_for_fingerprint(html):
    """極致嚴謹：剝除所有代碼與標籤，只針對『肉眼可見純文字』進行指紋比對"""
    # 移除所有腳本與樣式
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL|re.IGNORECASE)
    # 移除所有 HTML 標籤
    text_only = re.sub(r'<[^>]+>', ' ', html)
    # 壓縮多餘空白與換行，確保指紋純粹
    return " ".join(text_only.split())

def get_ssl_expiry(url):
    """強效 SSL 抓取：忽略驗證直接抓取憑證內容算日期"""
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
                # 計算剩餘天數 (UTC)
                remaining = cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()
                return f"{remaining.days}天"
    except Exception:
        return "N/A"

def check_sites():
    """執行全站健康與內容掃描"""
    # 讀取舊狀態紀錄
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    is_critical = False
    
    # 偽裝瀏覽器避免 WAF 阻擋
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            
            # 1. 產生乾淨的純文字指紋
            clean_content = clean_html_for_fingerprint(res.text)
            curr_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:8]
            
            # 2. 比對舊指紋
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = (old_hash is not None) and (curr_hash != old_hash)
            
            # 3. 基本健康檢測
            kw_ok = site['key'] in res.text
            ssl_info = get_ssl_expiry(site['url'])

            # 狀態判定邏輯
            status = "🟢 正常"
            finger = f"✅ 穩定({curr_hash})"
            
            if not kw_ok or res.status_code != 200:
                # 只有斷線或關鍵字消失才視為「危急狀態」
                status = "🔴 異常 (內容缺失)"
                is_critical = True
            elif hash_changed:
                # 內容異動僅視為「警示」
                status = "🟡 內容異動"
                finger = f"⚠️ 變動({old_hash}->{curr_hash})"

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            # 儲存新的指紋供下次比對
            new_state[site['name']] = {"hash": curr_hash}
            
        except Exception as e:
            # 處理 Timeout 或 DNS 解析失敗等網路層級錯誤
            results.append({
                "name": site['name'], "url": site['url'], "status": f"🔥 斷線({type(e).__name__})", 
                "ssl": "N/A", "latency": "0", "fingerprint": "N/A"
            })
            is_critical = True

    # 存檔以更新狀態
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
        
    return results, is_critical

# =====================================================================
# 3. 儀表板更新與 Teams 通報
# =====================================================================

def update_html(results):
    """霸道全覆蓋法：每次直接生成全新的 HTML，徹底消滅解析失敗的可能"""
    rows = ""
    for r in results:
        style = "status-green"
        if "異常" in r['status'] or "斷線" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>\n"""

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 完整 HTML 模板直接包在 Python 裡
    html_content = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="60">
    <title>TCB WEB INSPECTOR</title>
    <style>
        body {{ background: #0b0e14; color: #c9d1d9; font-family: sans-serif; padding: 20px; }}
        .dashboard-table {{ width: 100%; border-collapse: collapse; background: #161b22; box-shadow: 0 0 20px rgba(0,0,0,0.5); }}
        .dashboard-table th, td {{ border: 1px solid #30363d; padding: 15px; text-align: left; }}
        .dashboard-table th {{ background: #1f242c; color: #00f2ff; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .status-green {{ color: #2ecc71; border: 1px solid #2ecc71; }}
        .status-yellow {{ color: #f1c40f; border: 1px solid #f1c40f; }}
        .status-red {{ color: #e74c3c; border: 1px solid #e74c3c; }}
        .accent {{ color: #00f2ff; text-shadow: 0 0 5px #00f2ff; letter-spacing: 2px; }}
        a {{ color: #00f2ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1 class="accent">TCB WEB MONITORING CENTER</h1>
    <p>
        LAST UPDATE: <span id="update-time">{update_time}</span> | 
        <span style="color: #8b949e;">距離下次重整: <span id="secs">60</span>s</span>
    </p>
    
    <table class="dashboard-table">
        <thead>
            <tr><th>系統名稱</th><th>當前狀態</th><th>SSL 效期</th><th>回應延遲</th><th>指紋狀態</th><th>快速連結</th></tr>
        </thead>
        <tbody id="table-body">
{rows}
        </tbody>
    </table>

    <script>
        let timeLeft = 60;
        setInterval(() => {{
            timeLeft--;
            document.getElementById('secs').innerText = timeLeft;
            if (timeLeft <= 0) location.reload();
        }}, 1000);
    </script>
</body>
</html>"""

    # 直接強制覆蓋寫入檔案
    try:
        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(html_content)
        print("✅ HTML 儀表板已霸道更新完成。")
    except Exception as e:
        print(f"❌ HTML 寫入失敗: {e}")

def send_teams(results, is_critical):
    """向 Microsoft Teams 或 Power Automate 發送結構化告警"""
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: 
        print("⚠️ 找不到 TEAMS_WEBHOOK_URL 環境變數，略過發送。")
        return
        
    title = "🚨 系統緊急告警" if is_critical else "✅ 網站巡檢日報"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
        
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    
    try:
        res = requests.post(webhook, json=payload, timeout=10)
        print(f"📤 Teams 發送狀態碼: {res.status_code}")
    except Exception as e:
        print(f"❌ Teams 發送失敗: {e}")

# =====================================================================
# 4. 主程式流程控制
# =====================================================================

if __name__ == "__main__":
    print(f"⏰ 啟動監控任務: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. 執行檢測
    data, critical = check_sites()
    
    # 2. 更新本地網頁 (稍後由 Action 推送)
    update_html(data)
    
    # 3. 通報判斷
    current_minute = datetime.now().minute
    # 預設邏輯：出現緊急狀況，或是每個小時前 15 分鐘 (整點報時) 才發送。
    if critical or current_minute < 15:
        send_teams(data, critical)
    else:
        print("ℹ️ 系統狀態穩定且非通報週期，靜默執行完畢。")
