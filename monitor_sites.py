import requests
import ssl
import socket
import hashlib
import json
import os
import time
from datetime import datetime

# =====================================================================
# 1. 監控設定區
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
# 🌟 請替換為你的 GitHub Pages 網址
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" 

# =====================================================================
# 2. 深度檢測功能 (SSL, Fingerprint, Latency)
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
    """執行全站掃描與指紋比對"""
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
    
    # 偽裝瀏覽器以避免被 WAF 阻擋
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            content = res.text
            
            # A. 內容比對 (關鍵字檢查)
            kw_ok = site['key'] in content
            
            # B. 網頁指紋 (SHA256 防竄改)
            current_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:10]
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = old_hash and current_hash != old_hash
            
            # C. SSL 檢查
            ssl_info = get_ssl_expiry(site['url'])

            # 判定狀態邏輯
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
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", 
                "fingerprint": fingerprint_status, "hash": current_hash
            })
            new_state[site['name']] = {"hash": current_hash}

        except Exception as e:
            results.append({
                "name": site['name'], "url": site['url'], "status": f"🔥 斷線({type(e).__name__})",
                "ssl": "N/A", "latency": "0", "fingerprint": "N/A", "hash": "N/A"
            })
            has_critical_error = True

    # 更新狀態檔以供下次比對
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    
    return results, has_critical_error

# =====================================================================
# 3. 儀表板更新與通訊功能
# =====================================================================

def update_html_dashboard(results):
    """將結果寫入 index.html 模板"""
    if not os.path.exists(DASHBOARD_FILE):
        print("⚠️ 找不到 index.html，略過網頁更新。")
        return

    table_rows = ""
    for r in results:
        # 根據狀態決定 CSS 樣式
        status_style = "status-green"
        if "🚨" in r['status'] or "🔥" in r['status'] or "🔴" in r['status']:
            status_style = "status-red"
        elif "🟡" in r['status']:
            status_style = "status-yellow"

        table_rows += f"""
            <tr>
                <td>{r['name']}</td>
                <td><span class="status-badge {status_style}">{r['status']}</span></td>
                <td>{r['ssl']}</td>
                <td>{r['latency']}</td>
                <td><code>{r['fingerprint']}</code></td>
                <td><a href="{r['url']}" target="_blank">造訪網頁</a></td>
            </tr>
        """

    # 讀取 HTML 內容並尋找填充點
    with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
        html = f.read()

    try:
        # 使用 HTML 註解作為切割點
        parts = html.split('')
        if len(parts) < 2:
            print("❌ 找不到 HTML 填充標記，請確認 index.html 內容。")
            return
            
        new_html = parts[0] + '' + table_rows + '' + parts[2] if len(parts) > 2 else parts[0] + table_rows + parts[1]
        
        # 更新最後更新時間
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 這裡假設 HTML 裡有 <span id="update-time">...</span> 的結構
        import re
        new_html = re.sub(r'<span id="update-time">.*?</span>', f'<span id="update-time">{update_time}</span>', new_html)

        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(new_html)
        print("✅ HTML 儀表板已更新。")
    except Exception as e:
        print(f"❌ HTML 更新失敗: {e}")

def send_to_teams(results, is_urgent=False):
    """配合 Power Automate 欄位發送訊息"""
    webhook_url = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook_url: return

    report_title = "🚨 **網站安全緊急告警**" if is_urgent else "✅ **網站運行整點報時**"
    
    # 建立 Markdown 表格給 Teams
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"

    # 配合你 Power Automate 的 "message" 欄位
    payload = {
        "message": f"## {report_title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"
    }
    
    requests.post(webhook_url, json=payload)
    print("📤 訊息已發送至 Teams。")

# =====================================================================
# 4. 主程式流程
# =====================================================================

if __name__ == "__main__":
    print(f"⏰ 啟動監控任務: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. 執行核心檢測
    monitor_results, is_critical = check_sites()
    
    # 2. 自動更新本地 HTML 儀表板 (稍後由 GitHub Actions 推送)
    update_html_dashboard(monitor_results)
    
    # 3. 通報邏輯控制
    current_minute = datetime.now().minute
    # 規則：若是異常狀況 (is_critical) -> 立刻發送
    # 規則：若是整點 (每小時的前 15 分鐘週期) -> 發送平安報
    if is_critical or current_minute < 15:
        send_to_teams(monitor_results, is_urgent=is_critical)
    else:
        print("ℹ️ 系統狀態正常且非整點週期，略過 Teams 通知以減少干擾。")
