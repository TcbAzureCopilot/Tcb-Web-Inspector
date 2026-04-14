import requests
import ssl
import socket
import hashlib
import json
import os
import time
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

# 檔案路徑設定
STATE_FILE = "data/site_state.json"
DASHBOARD_FILE = "index.html"
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" # 這是你的儀表板連結

# =====================================================================
# 2. 核心檢測功能
# =====================================================================

def get_ssl_expiry(url):
    """取得 SSL 憑證剩餘天數"""
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %G')
                days_left = (expiry_date - datetime.now()).days
                return f"{days_left}天"
    except Exception:
        return "N/A"

def check_sites():
    """執行全站掃描"""
    # 讀取舊指紋紀錄
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    has_critical_error = False
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=20, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            content = res.text
            
            # A. 內容比對 (關鍵字)
            kw_ok = site['key'] in content
            
            # B. 網頁指紋 (防竄改)
            # 注意：若網頁有動態時間，指紋會變動。建議實作時可過濾掉 script 標籤。
            current_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:10]
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = old_hash and current_hash != old_hash
            
            # C. SSL 檢查
            ssl_info = get_ssl_expiry(site['url'])

            # 判定狀態
            status = "🟢 正常"
            fingerprint_status = "✅ 未變動"

            if hash_changed:
                status = "🚨 內容竄改預警"
                fingerprint_status = f"⚠️ 已變更({current_hash})"
                has_critical_error = True
            elif not kw_ok:
                status = "🟡 內容異常"
                has_critical_error = True
            elif res.status_code != 200:
                status = f"🔴 錯誤({res.status_code})"
                has_critical_error = True

            results.append({
                "name": site['name'],
                "url": site['url'],
                "status": status,
                "ssl": ssl_info,
                "latency": f"{latency}ms",
                "fingerprint": fingerprint_status,
                "time": datetime.now().strftime("%H:%M")
            })
            new_state[site['name']] = {"hash": current_hash}

        except Exception as e:
            results.append({
                "name": site['name'], "url": site['url'], "status": "🔥 斷線",
                "ssl": "N/A", "latency": "0", "fingerprint": "N/A", "time": "N/A"
            })
            has_critical_error = True

    # 更新狀態檔
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    
    return results, has_critical_error

# =====================================================================
# 3. 訊息發送邏輯
# =====================================================================

def send_to_teams(results, is_urgent=False):
    webhook_url = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook_url: return

    title = "🚨 監控系統異常告警" if is_urgent else "🌐 網頁監控整點報時"
    
    # 建立 Markdown 表格
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"

    payload = {
        "message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"
    }
    
    requests.post(webhook_url, json=payload)

if __name__ == "__main__":
    results, is_critical = check_sites()
    
    # 決定是否發送 Teams
    current_minute = datetime.now().minute
    
    # 邏輯：
    # 1. 只要有異常 (is_critical)，立刻發送。
    # 2. 每小時的前 15 分鐘週期 (整點)，發送一次正常報時。
    if is_critical or current_minute < 15:
        print("🚀 觸發發送條件，正在傳送至 Teams...")
        send_to_teams(results, is_urgent=is_critical)
    else:
        print("🤫 系統狀態正常且非整點，略過 Teams 通知。")
