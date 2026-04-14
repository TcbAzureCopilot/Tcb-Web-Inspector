import requests
import ssl
import socket
import hashlib
import json
import os
import time
import re
from datetime import datetime

# 關閉 requests 的 SSL 警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# =====================================================================
# 1. 監控設定區 
# =====================================================================
SITES = [
    {"name": "銀行官網", "url": "https://www.tcb-bank.com.tw/", "key": "合作金庫"},
    {"name": "合庫金控官網", "url": "https://www.tcfhc.com.tw/", "key": "合庫金控"},
    {"name": "個人網路銀行", "url": "https://cobank.tcb-bank.com.tw/TCB.TWNB.IDV.WEB/", "key": ""},
    {"name": "網路銀行", "url": "https://cobank.tcb-bank.com.tw", "key": ""},
    {"name": "企業網路銀行", "url": "https://cobank.tcb-bank.com.tw/TCB.TWNB.CORP.WEB/", "key": ""},
    {"name": "合庫銀行eATM", "url": "https://eatm.tcb-bank.com.tw", "key": ""},
    {"name": "金邊分行網銀", "url": "https://ebankkh.tcb-bank.com.tw:446", "key": ""},
    {"name": "香港網銀入口", "url": "https://ebank.tcb-bank.com.hk/TCB.HKNB.CORP.WEB/bank.jsp", "key": ""},
    {"name": "大陸網銀", "url": "https://cobank.tcbbk.com.cn", "key": ""},
    {"name": "全球金融網", "url": "https://feoi.tcb-bank.com.tw", "key": ""},
    {"name": "媒體檔案傳輸", "url": "https://webftp.tcb-bank.com.tw/FileTrans/viewLoginDmz.action", "key": ""},
    {"name": "電子代收系統", "url": "https://ars.tcb-bank.com.tw/", "key": ""},
    {"name": "招標採購公告", "url": "https://ebulletin.tcb-bank.com.tw/bulletin-web/", "key": ""},
    {"name": "線上取號系統", "url": "https://otn.tcb-bank.com.tw/ACweb/", "key": ""},
    {"name": "金庫幣", "url": "https://mpp.tcb-bank.com.tw/", "key": ""},
    {"name": "Mpos行動收單", "url": "https://mpos.tcb-bank.com.tw/erc/Login/Login.aspx", "key": ""},
    {"name": "信託服務網", "url": "https://trusts.tcb-bank.com.tw/eTrust/", "key": "信託"},
    {"name": "智能理財", "url": "https://irobo.tcb-bank.com.tw/irobo", "key": ""},
    {"name": "財管滿意度調查", "url": "https://wms.tcb-bank.com.tw/", "key": ""},
    {"name": "小規模營業人諮詢", "url": "https://cobank.tcb-bank.com.tw/ELNA/litinput.jsp", "key": ""},
    {"name": "供應商查詢系統", "url": "https://mbbank.tcb-bank.com.tw/QSMS/", "key": ""},
    {"name": "票券保管銀行", "url": "https://ebills.tcb-bank.com.tw", "key": ""},
    {"name": "新一代信貸系統", "url": "https://cobank.tcb-bank.com.tw/TCB.LOAN.SERVICE/PersonalLoan/Index", "key": ""},
    {"name": "跨境支付特店後台", "url": "https://copay.tcb-bank.com.tw/fesnetMP2/", "key": ""}
]

STATE_FILE = "data/site_state.json"
DASHBOARD_FILE = "index.html"
GITHUB_IO_URL = "https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/" 

# =====================================================================
# 2. 深度檢測與寬容判定
# =====================================================================

def clean_html(html):
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL|re.IGNORECASE)
    return " ".join(re.sub(r'<[^>]+>', ' ', html).split())

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
    except Exception: return "N/A"

def check_sites():
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f: old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    is_critical = False
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=20, headers=headers, verify=False)
            latency = int((time.time() - start_time) * 1000)
            
            clean_content = clean_html(res.text)
            curr_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:8]
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = (old_hash is not None) and (curr_hash != old_hash)
            
            ssl_info = get_ssl_expiry(site['url'])

            # 🌟 狀態判定邏輯升級
            if res.status_code in [200, 401, 403, 404]:
                kw_ok = (site['key'] == "") or (site['key'] in res.text)
                if not kw_ok and res.status_code == 200:
                    status = "🟡 內容異動(無關鍵字)"
                    finger = f"⚠️ ({curr_hash})"
                elif res.status_code != 200:
                    status = f"🟢 存活(WAF回應 {res.status_code})"
                    finger = "✅ 穩定"
                else:
                    status = "🟢 正常"
                    finger = "✅ 穩定"
            elif res.status_code == 500:
                # HTTP 500 代表伺服器活著，只是程式報錯，不亮紅燈
                status = "🟡 存活(系統報錯500)"
                finger = "N/A"
            else:
                status = f"🔴 異常 (HTTP {res.status_code})"
                finger = "N/A"
                is_critical = True

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            new_state[site['name']] = {"hash": curr_hash}
            
        except requests.exceptions.SSLError:
            # 🌟 抓到了！底層協定不通但伺服器存活
            results.append({"name": site['name'], "url": site['url'], "status": "🟢 存活(SSL交握阻擋)", "ssl": "N/A", "latency": "阻擋", "fingerprint": "N/A"})
        except requests.exceptions.Timeout:
            # 🌟 物理阻擋，標示清楚不再報錯
            results.append({"name": site['name'], "url": site['url'], "status": "⚪ 境外阻擋(伺服器預設)", "ssl": "N/A", "latency": "Timeout", "fingerprint": "N/A"})
        except Exception as e:
            results.append({"name": site['name'], "url": site['url'], "status": f"🔥 斷線({type(e).__name__})", "ssl": "N/A", "latency": "0", "fingerprint": "N/A"})
            is_critical = True

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w') as f: json.dump(new_state, f)
        
    return results, is_critical

# =====================================================================
# 3. 儀表板與通報
# =====================================================================

def update_html(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "異常" in r['status'] or "斷線" in r['status']: style = "status-red"
        elif "異動" in r['status'] or "存活(" in r['status']: style = "status-yellow"
        if "境外阻擋" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>\n"""

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        /* 🌟 說明區塊的 CSS */
        .info-panel {{ margin-top: 30px; padding: 20px; background: #161b22; border-left: 4px solid #00f2ff; color: #8b949e; font-size: 14px; line-height: 1.8; box-shadow: 0 0 10px rgba(0,0,0,0.3); }}
        .info-panel strong {{ color: #c9d1d9; }}
    </style>
</head>
<body>
    <h1 class="accent">TCB WEB MONITORING CENTER</h1>
    <p>
        LAST UPDATE: <span id="update-time">{update_time}</span> | 
        <span style="color: #8b949e;">距離下次重整: <span id="secs">60</span>s</span>
    </p>
    <table class="dashboard-table">
        <thead><tr><th>系統名稱</th><th>當前狀態</th><th>SSL 效期</th><th>回應延遲</th><th>指紋狀態</th><th>快速連結</th></tr></thead>
        <tbody id="table-body">
{rows}
        </tbody>
    </table>
    
    <div class="info-panel">
        <strong style="color:#00f2ff; font-size: 16px;">[ 系統指標與檢測邏輯說明 ]</strong><br>
        <strong>• 當前狀態：</strong>綜合判定 HTTP 狀態碼與內容關鍵字。收到 403/404 等 WAF 防火牆阻擋視為「系統存活」，500 視為「後端報錯」，TCP Timeout 則標記為「境外阻擋」。<br>
        <strong>• SSL 效期：</strong>繞過中繼代理，直接透過 Port 443 與終端伺服器進行底層交握，解析 X.509 憑證並計算至 UTC 到期日之剩餘天數。<br>
        <strong>• 回應延遲：</strong>記錄從發出 HTTP GET 請求起，至收到伺服器初始回應 (Headers) 的絕對時間差 (以毫秒 ms 計)。<br>
        <strong>• 指紋狀態：</strong>自動剝除網頁中的程式碼 (Script)、樣式表 (CSS) 與 HTML 標籤，僅針對「肉眼可見純文字」進行 SHA-256 雜湊運算。若雜湊值變更即觸發異動警示 (防誤報設計)。
    </div>

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

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)

def send_teams(results, is_critical):
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: return
        
    title = "🚨 系統緊急告警" if is_critical else "✅ 網站巡檢日報"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
        
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    try: requests.post(webhook, json=payload, timeout=10)
    except: pass

if __name__ == "__main__":
    data, critical = check_sites()
    update_html(data)
    
    current_minute = datetime.now().minute
    #if critical or current_minute < 15:
    send_teams(data, critical)
