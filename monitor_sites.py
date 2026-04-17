import requests
import ssl
import socket
import hashlib
import json
import os
import time
import re
import base64
from datetime import datetime
import urllib3
from playwright.sync_api import sync_playwright

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================================
# 1. 監控設定區 (完整 32 個站點)
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
# 2. 核心檢測與截圖邏輯
# =====================================================================

def clean_html_content(html):
    html = re.sub(r'(?is)<script.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?</style>', '', html)
    html = re.sub(r'(?s)<[^>]+>', '', html)
    return "".join(html.split())

def take_screenshot(browser_context, url):
    """執行背景截圖並回傳 Base64 文字"""
    try:
        page = browser_context.new_page()
        page.set_viewport_size({"width": 1280, "height": 720})
        # 設定 30 秒逾時，等待網頁完全載入
        page.goto(url, timeout=30000, wait_until="load")
        time.sleep(3) # 額外多等 3 秒讓 JavaScript 跑完
        img_bytes = page.screenshot(type='jpeg', quality=60)
        page.close()
        return base64.b64encode(img_bytes).decode('utf-8')
    except Exception as e:
        print(f"  ❌ 截圖失敗: {e}")
        return None

def check_sites():
    baseline = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as f: baseline = json.load(f)
        except: pass

    results = []
    critical_count = 0
    new_baseline = {}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'}

    # 啟動 Playwright 瀏覽器引擎
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)

        for site in SITES:
            status = "🟢 正常"
            latency = 0
            finger = "N/A"
            b64_img = ""
            
            try:
                # 針對特定慢速網站調整逾時
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
                    status = f"🔥 錯誤({res.status_code})"
                    critical_count += 1

            except Exception:
                status = "🔥 斷線(連線失敗)"
                critical_count += 1
                latency = 0

            # 🌟 只有「異常」才截圖，節省 Actions 時間與資源
            if "正常" not in status:
                print(f"📸 正在為異常站點拍照: {site['name']}...")
                b64_img = take_screenshot(context, site['url'])

            results.append({
                "id": site['id'], "dept": site['dept'], "name": site['name'],
                "status": status, "latency": f"{latency}ms" if latency > 0 else "0ms",
                "finger": finger, "url": site['url'], "img": b64_img
            })

        browser.close()

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w', encoding='utf-8') as f: json.dump(new_baseline, f)
    return results, critical_count

# =====================================================================
# 3. 儀表板與通知
# =====================================================================

def update_dashboard(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "斷線" in r['status'] or "錯誤" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        img_html = "N/A"
        if r['img']:
            # 點擊圖片會呼叫下方的 openModal 放大
            img_html = f'<img src="data:image/jpeg;base64,{r["img"]}" class="thumb" onclick="openModal(this.src)">'

        rows += f"""<tr>
            <td>{r['id']}</td>
            <td>{r['dept']}</td>
            <td>{r['name']}</td>
            <td><span class="status-badge {style}">{r['status']}</span></td>
            <td>{r['latency']}</td>
            <td>{img_html}</td>
            <td><a href="{r['url']}" target="_blank">造訪</a></td>
        </tr>\n"""

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>TCB WEB INSPECTOR</title>
    <style>
        body {{ background: #0b0e14; color: #c9d1d9; font-family: sans-serif; padding: 20px; }}
        .dashboard-table {{ width: 100%; border-collapse: collapse; background: #161b22; }}
        .dashboard-table th, td {{ border: 1px solid #30363d; padding: 12px; text-align: left; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .status-green {{ color: #2ecc71; border: 1px solid #2ecc71; }}
        .status-yellow {{ color: #f1c40f; border: 1px solid #f1c40f; }}
        .status-red {{ color: #e74c3c; border: 1px solid #e74c3c; }}
        .thumb {{ width: 100px; cursor: pointer; border: 1px solid #444; }}
        .thumb:hover {{ border-color: #00f2ff; }}
        #modal {{ display:none; position:fixed; z-index:99; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.9); text-align:center; }}
        #modalImg {{ max-width: 90%; max-height: 90%; margin-top: 2%; border: 2px solid #fff; }}
    </style>
</head>
<body>
    <h1>TCB WEB MONITORING CENTER</h1>
    <p>LAST UPDATE: {update_time}</p>
    <table class="dashboard-table">
        <thead><tr>
            <th>序號</th><th>科別</th><th>系統</th><th>狀態</th><th>延遲</th><th>即時截圖(點圖放大)</th><th>連結</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
    <div id="modal" onclick="this.style.display='none'"><img id="modalImg"></div>
    <script>
        function openModal(src) {{
            document.getElementById('modal').style.display='block';
            document.getElementById('modalImg').src = src;
        }}
    </script>
</body>
</html>"""
    with open(DASHBOARD_FILE, 'w', encoding='utf-8') as f: f.write(html)

def notify_teams(results, critical_count):
    if not TEAMS_WEBHOOK: return
    is_crit = critical_count > 0
    if is_crit or datetime.now().minute < 15:
        title = "🚨 **TCB 系統巡檢告警**" if is_crit else "✅ **TCB 系統巡檢日報**"
        table = "| 序號 | 系統 | 狀態 | 延遲 |\n| :--- | :--- | :--- | :--- |\n"
        for r in results: 
            table += f"| {r['id']} | {r['name']} | {r['status']} | {r['latency']} |\n"
        
        msg = f"{title}\n\n**異常數量**：{critical_count}\n\n{table}\n\n[📊 查看即時儀表板(含截圖)](https://TcbAzureCopilot.github.io/Tcb-Web-Inspector/)"
        try: requests.post(TEAMS_WEBHOOK, json={"message": msg}, timeout=10)
        except: pass

if __name__ == "__main__":
    res_data, crit_cnt = check_sites()
    update_dashboard(res_data)
    notify_teams(res_data, crit_cnt)
