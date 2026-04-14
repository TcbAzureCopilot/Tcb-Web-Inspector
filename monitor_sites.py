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
# 1. 監控設定區 (採用靜態資源監控法)
# =====================================================================
SITES = [
    {"name": "銀行官網", "url": "https://www.tcb-bank.com.tw/", "key": "合作金庫"},
    {"name": "合庫金控官網", "url": "https://www.tcfhc.com.tw/", "key": "合庫金控"},
    
    # 🌟 以下為改測靜態資源 (favicon.ico 或 logo) 的系統，key 設為空字串
    {"name": "個人網路銀行", "url": "https://cobank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "網路銀行", "url": "https://cobank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "企業網路銀行", "url": "https://cobank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "合庫銀行eATM", "url": "https://eatm.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "金邊分行網銀", "url": "https://ebankkh.tcb-bank.com.tw:446/favicon.ico", "key": ""},
    {"name": "香港網銀入口", "url": "https://ebank.tcb-bank.com.hk/favicon.ico", "key": ""},
    {"name": "大陸網銀", "url": "https://cobank.tcbbk.com.cn/favicon.ico", "key": ""},
    
    {"name": "全球金融網", "url": "https://feoi.tcb-bank.com.tw", "key": "全球金融網"},
    {"name": "媒體檔案傳輸", "url": "https://webftp.tcb-bank.com.tw/FileTrans/viewLoginDmz.action", "key": "密碼"},
    
    # 🌟 靜態資源群
    {"name": "電子代收系統", "url": "https://ars.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "招標採購公告", "url": "https://ebulletin.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "線上取號系統", "url": "https://otn.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "金庫幣", "url": "https://mpp.tcb-bank.com.tw/favicon.ico", "key": ""},
    
    {"name": "Mpos行動收單", "url": "https://mpos.tcb-bank.com.tw/erc/Login/Login.aspx", "key": "登入"},
    {"name": "信託服務網", "url": "https://trusts.tcb-bank.com.tw/eTrust/", "key": "信託"},
    
    # 🌟 靜態資源群
    {"name": "智能理財", "url": "https://irobo.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "財管滿意度調查", "url": "https://wms.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "小規模營業人諮詢", "url": "https://cobank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "供應商查詢系統", "url": "https://mbbank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "票券保管銀行", "url": "https://ebills.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "新一代信貸系統", "url": "https://cobank.tcb-bank.com.tw/favicon.ico", "key": ""},
    {"name": "跨境支付特店後台", "url": "https://copay.tcb-bank.com.tw/favicon.ico", "key": ""}
]

STATE_FILE = "data/site_state.json"
DASHBOARD_FILE = "index.html"
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" 

# =====================================================================
# 2. 深度檢測功能 (支援靜態資源自動辨識)
# =====================================================================

def clean_html_for_fingerprint(html):
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL|re.IGNORECASE)
    text_only = re.sub(r'<[^>]+>', ' ', html)
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
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            
            content_type = res.headers.get('Content-Type', '').lower()
            
            # 🌟 智慧判斷：是網頁還是檔案？
            if 'text/html' in content_type:
                clean_content = clean_html_for_fingerprint(res.text)
                curr_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:8]
                kw_ok = (site['key'] == "") or (site['key'] in res.text)
            else:
                # 若是圖片(favicon)或靜態檔，直接針對二進位檔案做指紋，且必過關鍵字檢查
                curr_hash = hashlib.sha256(res.content).hexdigest()[:8]
                kw_ok = True 

            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = (old_hash is not None) and (curr_hash != old_hash)
            
            ssl_info = get_ssl_expiry(site['url'])

            status = "🟢 正常"
            finger = f"✅ 穩定({curr_hash})"
            
            if res.status_code != 200:
                status = f"🔴 異常 (HTTP {res.status_code})"
                is_critical = True
            elif not kw_ok:
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
            
        except requests.exceptions.Timeout:
            results.append({
                "name": site['name'], "url": site['url'], "status": "🔥 斷線(連線逾時)", 
                "ssl": "N/A", "latency": "Timeout", "fingerprint": "N/A"
            })
            is_critical = True
        except Exception as e:
            results.append({
                "name": site['name'], "url": site['url'], "status": f"🔥 斷線({type(e).__name__})", 
                "ssl": "N/A", "latency": "0", "fingerprint": "N/A"
            })
            is_critical = True

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
        
    return results, is_critical

# =====================================================================
# 3. 儀表板更新與 Teams 通報 (防爆檔版本)
# =====================================================================

def update_html(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "異常" in r['status'] or "斷線" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>\n"""

    if os.path.exists(DASHBOARD_FILE):
        try:
            with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            
            header_part = content.split('')[0]
            footer_part = content.split('')[1]
            new_content = header_part + "\n" + rows + "" + footer_part
            
            update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            new_content = re.sub(r'<span id="update-time">.*?</span>', f'<span id="update-time">{update_time}</span>', new_content)

            with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
                f.write(new_content)
        except Exception as e:
            print(f"❌ HTML 寫入失敗: {e}")

def send_teams(results, is_critical):
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: return
        
    title = "🚨 系統緊急告警" if is_critical else "✅ 網站巡檢日報"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
        
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    requests.post(webhook, json=payload, timeout=10)

if __name__ == "__main__":
    data, critical = check_sites()
    update_html(data)
    
    # 通報邏輯：出現緊急狀況，或是每小時前15分鐘(整點)，才發 Teams
    current_minute = datetime.now().minute
    if critical or current_minute < 15:
        send_teams(data, critical)
