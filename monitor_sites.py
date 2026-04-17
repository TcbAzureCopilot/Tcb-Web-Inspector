import requests
import ssl
import socket
import hashlib
import json
import os
import time
import re
import base64  # 🌟 新增
from datetime import datetime, timezone
import urllib3
from playwright.sync_api import sync_playwright # 🌟 新增

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# [SITES 設定區保持不變...]

STATE_FILE = "data/fingerprints.json"
DASHBOARD_FILE = "index.html"
TEAMS_WEBHOOK = os.environ.get('TEAMS_WEBHOOK_URL')

# =====================================================================
# 2. 核心檢測與截圖
# =====================================================================

def clean_html_content(html):
    html = re.sub(r'(?is)<script.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?</style>', '', html)
    html = re.sub(r'(?s)<[^>]+>', '', html)
    return "".join(html.split())

def take_screenshot(browser_context, url):
    """🌟 執行背景截圖並回傳 Base64 文字"""
    try:
        page = browser_context.new_page()
        # 設定較小的視窗以節省空間
        page.set_viewport_size({"width": 1024, "height": 768})
        page.goto(url, timeout=30000, wait_until="load")
        time.sleep(2) # 額外等待 2 秒確保圖片載入
        
        # 截取縮圖以維持 Base64 長度
        img_bytes = page.screenshot(type='jpeg', quality=60)
        page.close()
        return base64.b64encode(img_bytes).decode('utf-8')
    except Exception as e:
        print(f"截圖失敗 ({url}): {e}")
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
    headers = {'User-Agent': 'Mozilla/5.0...'}

    # 🌟 啟動瀏覽器引擎
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)

        for site in SITES:
            status = "🟢 正常"
            latency = 0
            finger = "N/A"
            b64_img = "" # 儲存截圖
            
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
                    status = f"🔥 錯誤({res.status_code})"
                    critical_count += 1

            except Exception as e:
                status = "🔥 斷線(連線失敗)"
                critical_count += 1
                latency = 0

            # 🌟 如果狀態不正常，進行截圖
            if "正常" not in status:
                print(f"📸 正在為異常站點截圖: {site['name']}")
                b64_img = take_screenshot(context, site['url'])

            results.append({
                "id": site['id'], "dept": site['dept'], "name": site['name'],
                "status": status, "latency": f"{latency}ms",
                "finger": finger, "url": site['url'], "img": b64_img
            })

        browser.close()

    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, 'w', encoding='utf-8') as f: json.dump(new_baseline, f)
    return results, critical_count

# =====================================================================
# 3. 儀表板生成 (加入圖片顯示與點擊放大)
# =====================================================================

def update_dashboard(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "斷線" in r['status'] or "錯誤" in r['status']: style = "status-red"
        elif "異動" in r['status']: style = "status-yellow"
        
        # 🌟 處理圖片顯示
        img_html = "N/A"
        if r['img']:
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
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .status-green {{ color: #2ecc71; border: 1px solid #2ecc71; }}
        .status-yellow {{ color: #f1c40f; border: 1px solid #f1c40f; }}
        .status-red {{ color: #e74c3c; border: 1px solid #e74c3c; }}
        .thumb {{ width: 80px; height: 50px; object-fit: cover; cursor: pointer; border: 1px solid #30363d; }}
        .thumb:hover {{ border-color: #00f2ff; }}
        /* Modal 樣式 */
        #modal {{ display:none; position:fixed; z-index:99; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.9); }}
        #modalImg {{ margin: auto; display: block; max-width: 90%; max-height: 90%; padding-top: 40px; }}
    </style>
</head>
<body>
    <h1>TCB WEB MONITORING CENTER</h1>
    <p>LAST UPDATE: {update_time}</p>
    <table class="dashboard-table">
        <thead><tr>
            <th>序號</th><th>科別</th><th>系統名稱</th><th>當前狀態</th><th>回應延遲</th><th>即時畫面</th><th>連結</th>
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

# [notify_teams 保持不變，因為 Teams Webhook 帶不動大圖，建議維持表格文字]

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
