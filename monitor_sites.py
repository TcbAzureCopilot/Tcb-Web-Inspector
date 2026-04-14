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
# 嚴謹化邏輯：過濾動態內容
# =====================================================================
def clean_html(html):
    """剔除網頁中容易變動的動態部分，減少誤報"""
    # 移除所有 <script> 內容
    html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL)
    # 移除所有 <style> 內容 (有時會有動態路徑)
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL)
    # 移除隱藏的 input (常見 CSRF Token)
    html = re.sub(r'<input type="hidden".*?>', '', html)
    # 移除註解
    html = re.sub(r'', '', html, flags=re.DOTALL)
    return html

def get_ssl_expiry(url):
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
    except: return "檢測中"

def check_sites():
    old_state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                old_state = json.load(f)
        except: pass

    results = []
    new_state = {}
    has_critical = False
    headers = {'User-Agent': 'Mozilla/5.0'}

    for site in SITES:
        try:
            start_time = time.time()
            res = requests.get(site['url'], timeout=25, headers=headers)
            latency = int((time.time() - start_time) * 1000)
            
            # 🌟 嚴謹指紋比對：只比對「乾淨」的內容
            cleaned_content = clean_html(res.text)
            curr_hash = hashlib.sha256(cleaned_content.encode('utf-8')).hexdigest()[:12]
            
            old_hash = old_state.get(site['name'], {}).get('hash')
            hash_changed = old_hash and curr_hash != old_hash
            
            kw_ok = site['key'] in res.text
            ssl_info = get_ssl_expiry(site['url'])

            status = "🟢 正常"
            finger = "✅ 穩定"
            
            # 只有當關鍵字消失 OR 狀態碼錯誤時才視為緊急異常
            if not kw_ok or res.status_code != 200:
                status = "🔴 異常/內容缺失"
                has_critical = True
            # 指紋變動僅視為「提醒」，不一定觸發緊急告警（除非你希望它很嚴格）
            elif hash_changed:
                status = "🟡 內容微調"
                finger = f"⚠️ 變動({curr_hash})"
                # 若要極度嚴謹，這裡 has_critical 可設為 False，僅在儀表板更新

            results.append({
                "name": site['name'], "url": site['url'], "status": status,
                "ssl": ssl_info, "latency": f"{latency}ms", "fingerprint": finger
            })
            new_state[site['name']] = {"hash": curr_hash}
        except Exception as e:
            results.append({"name": site['name'], "url": site['url'], "status": "🔥 斷線", "ssl": "N/A", "latency": "0", "fingerprint": "N/A"})
            has_critical = True

    with open(STATE_FILE, 'w') as f:
        json.dump(new_state, f)
    return results, has_critical

# =====================================================================
# 儀表板更新：修正 HTML 注入
# =====================================================================
def update_html(results):
    rows = ""
    for r in results:
        style = "status-green"
        if "正常" not in r['status'] and "微調" not in r['status']: style = "status-red"
        if "微調" in r['status']: style = "status-yellow"
        
        rows += f"""<tr><td>{r['name']}</td><td><span class="status-badge {style}">{r['status']}</span></td><td>{r['ssl']}</td><td>{r['latency']}</td><td><code>{r['fingerprint']}</code></td><td><a href="{r['url']}" target="_blank">造訪</a></td></tr>"""

    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            html = f.read()
        
        # 使用簡單的 Marker 替換
        parts = html.split('')
        header = parts[0]
        footer = parts[1].split('')[1]
        
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_html = f"{header}{rows}{footer}"
        new_html = re.sub(r'LAST UPDATE: <span id="update-time">.*?</span>', f'LAST UPDATE: <span id="update-time">{update_time}</span>', new_html)

        with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
            f.write(new_html)

def send_teams(results, is_critical):
    webhook = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook: return
    # 🌟 只有「真正異常」或是「整點」才發 Teams
    title = "🚨 系統緊急告警" if is_critical else "✅ 定時巡檢報告"
    table = "| 系統 | 狀態 | SSL | 延遲 | 指紋 |\n| :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        table += f"| {r['name']} | {r['status']} | {r['ssl']} | {r['latency']} | {r['fingerprint']} |\n"
    
    payload = {"message": f"## {title}\n\n{table}\n\n[📊 點此查看即時監控儀表板]({GITHUB_IO_URL})"}
    requests.post(webhook, json=payload)

if __name__ == "__main__":
    data, critical = check_sites()
    update_html(data)
    # 僅在嚴重錯誤或整點時發送訊息
    if critical or datetime.now().minute < 15:
        send_teams(data, critical)
