import requests
import ssl
import socket
import hashlib
import json
import os
import time
import re
from datetime import datetime, timezone
import urllib3

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================================
# 1. 監控設定區 (同步地端 32 個站點，包含 ID 與 Dept)
# =====================================================================
SITES = [
    {"id": 1,  "dept": "OA", "name": "銀行官網", "url": "https://www.tcb-bank.com.tw/"},
    {"id": 2,  "dept": "OA", "name": "合庫金控官網", "url": "https://www.tcfhc.com.tw/"},
    {"id": 3,  "dept": "EA", "name": "個人網路銀行", "url": "https://cobank.tcb-bank.com.tw/TCB.TWNB.IDV.WEB/"},
    {"id": 4,  "dept": "EA", "name": "網路銀行", "url": "https://cobank.tcb-bank.com.tw"},
    {"id": 5,  "dept": "EA", "name": "個人網銀-信用卡/金融卡專區", "url": "https://cobank.tcb-bank.com.tw/TCB.TWNB.IDV.WEB/ccConsole.jsp"},
    {"id": 6,  "dept": "EA", "name": "企業網路銀行", "url": "https://cobank.tcb-bank.com.tw/TCB.TWNB.CORP.WEB/"},
    {"id": 7,  "dept": "EA", "name": "合庫銀行eATM", "url": "https://eatm.tcb-bank.com.tw"},
    {"id": 8,  "dept": "EA", "name": "金邊分行網銀", "url": "https://ebankkh.tcb-bank.com.tw:446/TCB.PPNB.CORP.WEB/bank.faces"},
    {"id": 9,  "dept": "EA", "name": "香港網銀入口", "url": "https://ebank.tcb-bank.com.hk/TCB.HKNB.CORP.WEB/bank.jsp"},
    {"id": 10, "dept": "EA", "name": "大陸網銀", "url": "https://cobank.tcbbk.com.cn"},
    {"id": 11, "dept": "EA", "name": "合作金庫全球金融網", "url": "https://feoi.tcb-bank.com.tw"},
    {"id": 12, "dept": "OA", "name": "智能客服", "url": "https://robot.tcb-bank.com.tw/Webhook/"},
    {"id": 13, "dept": "OA", "name": "媒體檔案傳輸系統", "url": "https://webftp.tcb-bank.com.tw/FileTrans/viewLoginDmz.action"},
    {"id": 14, "dept": "OA", "name": "學費代收系統", "url": "https://ars.tcb-bank.com.tw/"},
    {"id": 15, "dept": "OA", "name": "招標採購公告系統", "url": "https://ebulletin.tcb-bank.com.tw/bulletin-web/"},
    {"id": 16, "dept": "OA", "name": "合作金庫-線上取號", "url": "https://otn.tcb-bank.com.tw/ACweb/"},
    {"id": 17, "dept": "OA", "name": "數位學習", "url": "https://tcb-elearning.tcb-bank.com.tw/RWD/LoginPage.aspx"},
    {"id": 18, "dept": "AP4", "name": "金庫幣", "url": "https://mpp.tcb-bank.com.tw/"},
    {"id": 19, "dept": "AP4", "name": "Mpos行動收單", "url": "https://mpos.tcb-bank.com.tw/erc/Login/Login.aspx"},
    {"id": 20, "dept": "AP4", "name": "EPGW(電子化繳費平台)", "url": "https://epgw.tcb-bank.com.tw/epgw-madm/"},
    {"id": 21, "dept": "AP4", "name": "信託服務網", "url": "https://trusts.tcb-bank.com.tw/eTrust/"},
    {"id": 22, "dept": "AP4", "name": "智能理財", "url": "https://irobo.tcb-bank.com.tw/irobo"},
    {"id": 23, "dept": "AP4", "name": "財管滿意度調查", "url": "https://wms.tcb-bank.com.tw/"},
    {"id": 24, "dept": "AP3", "name": "企業線上諮詢", "url": "https://cobank.tcb-bank.com.tw/ELNA/epinput.jsp"},
    {"id": 25, "dept": "AP3", "name": "微企合E貸線上諮詢", "url": "https://cobank.tcb-bank.com.tw/ELNA/esinput.jsp"},
    {"id": 26, "dept": "EA", "name": "e帳單代收系統", "url": "https://ebilling.tcb-bank.com.tw"},
    {"id": 27, "dept": "EA", "name": "供應商查詢系統", "url": "https://mbbank.tcb-bank.com.tw/QSMS/"},
    {"id": 28, "dept": "EA", "name": "金融友善服務專區", "url": "https://cobank.tcb-bank.com.tw/TCB.BFNB.IDV.WEB"},
    {"id": 29, "dept": "EA", "name": "票券保管銀行", "url": "https://ebills.tcb-bank.com.tw/ebills/logins"},
    {"id": 30, "dept": "EA", "name": "新一代信貸系統", "url": "https://cobank.tcb-bank.com.tw/TCB.LOAN.SERVICE/PersonalLoan/Index"},
    {"id": 31, "dept": "EA", "name": "跨境支付特店後台", "url": "https://copay.tcb-bank.com.tw/fesnetMP2/"},
    {"id": 32, "dept": "AP3", "name": "客戶滿意度問卷系統", "url": "https://css.tcb-bank.com.tw/"}
]

STATE_FILE = "data/fingerprints.json"
DASHBOARD_FILE = "index.html"
TEAMS_WEBHOOK = os.environ.get('TEAMS_WEBHOOK_URL')

# =====================================================================
# 2. 核心檢測與指紋
# =====================================================================

def clean_html_content(html):
    html = re.sub(r'(?is)<script.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?</style>', '', html)
    html = re.sub(r'(?s)<[^>]+>', '', html)
    return "".join(html.split())

def check_sites():
    baseline = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as f: baseline = json.load(f)
        except: pass

    results = []
    critical_count = 0
    new_baseline = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }

    for site in SITES:
        status = "🟢 正常"
        latency = 0
        finger = "N/A"
        
        try:
            timeout = 45 if (":446" in site['url'] or "Mpos" in site['name']) else 20
            start = time.time()
            res = requests.get(site['url'], timeout=timeout, headers=headers, verify=False, allow_redirects=True)
            latency = int((time.time() - start) * 1000)

            content_text = clean_html_content(res.text)
            finger = hashlib.sha256(content_text.encode('utf-8')).hexdigest()[:8]
            new_baseline[site['name']] = finger
            
            if site['name'] in baseline and baseline[site['name']] != finger:
                status = "🟠 內容異動"

            if res.status_code != 200:
                if res.status_code >= 500:
                    status = f"🔥 服務錯誤({res.status_code})"
                    critical_count += 1
                elif res.status_code in [401, 403, 404]:
                    status = f"🟢 存活(WAF回應 {res.status_code})"
                else:
                    status = f"🟡 有回應({res.status_code})"

        except requests.exceptions.Timeout:
            status = "⚪ 境外阻擋(Timeout)"
            latency = "Timeout"
        except Exception:
            status = "🔥 斷線(連線失敗)"
            critical_count += 1
            latency = 0

        results.append({
            "id": site['id'], "dept": site['dept'], "name": site['name'],
            "status": status, "latency": f"{latency}ms" if isinstance(latency, int) else latency,
            "finger": finger, "url": site['url']
        })

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w', encoding='utf-8') as f: json.dump(new_baseline, f)
    return results, critical_count

# =====================================================================
# 3. 儀表板生成
# =====================================================================

def update_dashboard(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "斷線" in r['status'] or "錯誤" in r['status']: style = "status-red"
        elif "存活" in r['status'] or "異動" in r['status'] or "阻擋" in r['status']: style = "status-yellow"
        
        # 嚴格對齊 7 個資料格
        rows += f"""<tr>
            <td>{r['id']}</td>
            <td>{r['dept']}</td>
            <td>{r['name']}</td>
            <td><span class="status-badge {style}">{r['status']}</span></td>
            <td>{r['latency']}</td>
            <td><code>{r['finger']}</code></td>
            <td><a href="{r['url']}" target="_blank">造訪</a></td>
        </tr>\n"""

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="60">
    <title>TCB WEB INSPECTOR</title>
    <style>
        body {{ background: #0b0e14; color: #c9d1d9; font-family: sans-serif; padding: 20px; }}
        .dashboard-table {{ width: 100%; border-collapse: collapse; background: #161b22; margin-top: 20px; }}
        .dashboard-table th, td {{ border: 1px solid #30363d; padding: 12px; text-align: left; }}
        .dashboard-table th {{ background: #1f242c; color: #00f2ff; font-size: 14px; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .status-green {{ color: #2ecc71; border: 1px solid #2ecc71; background: rgba(46,204,113,0.1); }}
        .status-yellow {{ color: #f1c40f; border: 1px solid #f1c40f; background: rgba(241,196,15,0.1); }}
        .status-red {{ color: #e74c3c; border: 1px solid #e74c3c; background: rgba(231,76,60,0.1); }}
        a {{ color: #00f2ff; text-decoration: none; }}
        code {{ color: #a5d6ff; font-family: monospace; font-size: 14px; }}
        .accent {{ color: #00f2ff; letter-spacing: 2px; text-shadow: 0 0 5px #00f2ff; }}
        .info-panel {{ margin-top: 30px; padding: 20px; background: #161b22; border-left: 4px solid #00f2ff; color: #8b949e; font-size: 14px; line-height: 1.8; }}
    </style>
</head>
<body>
    <h1 class="accent">TCB WEB MONITORING CENTER</h1>
    <p>LAST UPDATE: {update_time} | 距離下一次重整: <span id="secs" style="color:#00f2ff">60</span>s</p>
    <table class="dashboard-table">
        <thead><tr>
            <th>序號</th>
            <th>科別</th>
            <th>系統名稱</th>
            <th>當前狀態</th>
            <th>回應延遲</th>
            <th>指紋狀態</th>
            <th>系統連結</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
    <div class="info-panel">
        <strong style="color:#00f2ff">[ 系統指標與檢測邏輯說明 ]</strong><br>
        • <strong>當前狀態：</strong>綜合判定 HTTP 狀態碼。收到 403/404 等 WAF 防火牆阻擋視為「系統存活」，500 視為「後端報錯」。<br>
        • <strong>回應延遲：</strong>記錄從發出 HTTP GET 請求起，至收到伺服器初始回應的絕對時間差 (ms)。<br>
        • <strong>指紋狀態：</strong>自動剝除程式碼與 HTML 標籤，針對純文字進行 SHA-256 雜湊運算。若變更即觸發異動警示。<br>
        • <strong>自動更新：</strong>由地端排程觸發 GitHub Actions 定時執行巡檢並同步至此網頁。
    </div>
    <script>
        let timeLeft = 60;
        setInterval(() => {{
            timeLeft--;
            let el = document.getElementById('secs');
            if(el) el.innerText = timeLeft;
            if (timeLeft <= 0) location.reload();
        }}, 1000);
    </script>
</body>
</html>"""
    with open(DASHBOARD_FILE, 'w', encoding='utf-8') as f: f.write(html)

def notify_teams(results, critical_count):
    if not TEAMS_WEBHOOK: return
    is_crit = critical_count > 0
    
    if is_crit or datetime.now().minute < 15:
        title = "🚨 **TCB 系統巡檢告警**" if is_crit else "✅ **TCB 系統巡檢日報**"
        
        # 嚴格使用 \n 換行建立 Markdown 表格
        table = "| 序號 | 系統 | 狀態 | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
        for r in results: 
            table += f"| {r['id']} | {r['name']} | {r['status']} | {r['latency']} | {r['finger']} |\n"
        
        # 絕對不能混用 <br>，全部改用 \n\n 來做段落分隔
        msg = f"{title}\n\n**異常數量**：{critical_count}\n\n{table}\n\n[📊 查看即時儀表板](https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/)"
        
        payload = {"message": msg}
        try: 
            requests.post(TEAMS_WEBHOOK, json=payload, timeout=10)
        except Exception as e: 
            print(f"Teams 發送失敗: {e}")

if __name__ == "__main__":
    res_data, crit_cnt = check_sites()
    update_dashboard(res_data)
    notify_teams(res_data, crit_cnt)
