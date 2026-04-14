import requests
import os
import json
from datetime import datetime

# 🌟 監控清單 (你可以自行增加到 15 個)
SITES = [
    {"name": "銀行官網", "url": "https://www.google.com", "key": "Google"}, # 先用Google測
    {"name": "網路銀行", "url": "https://www.bot.com.tw", "key": "臺灣銀行"},
    {"name": "信用卡申請", "url": "https://www.tcb-bank.com.tw", "key": "合作金庫"},
]

def check_all_sites():
    report_lines = []
    has_error = False
    
    for site in SITES:
        try:
            # 設定 10 秒超時防止被卡死
            res = requests.get(site['url'], timeout=10)
            
            # 判斷狀態
            if res.status_code == 200:
                if site['key'] in res.text:
                    status = "🟢 正常"
                else:
                    status = "🟡 內容異常 (關鍵字缺失)"
                    has_error = True
            else:
                status = f"🔴 錯誤 (代碼: {res.status_code})"
                has_error = True
        except Exception as e:
            status = f"🔥 斷線 ({type(e).__name__})"
            has_error = True
        
        report_lines.append(f"| {site['name']} | {status} | [連結]({site['url']}) |")

    # 組合 Markdown 表格
    table = "| 系統名稱 | 狀態 | 快速跳轉 |\n| :--- | :--- | :--- |\n" + "\n".join(report_lines)
    
    return {
        "title": f"🌐 網頁監控戰報 ({datetime.now().strftime('%H:%M')})",
        "status_report": table,
        "is_alert": "Yes" if has_error else "No"
    }

def send_to_power_automate(data):
    webhook_url = os.environ.get('TEAMS_WEBHOOK_URL')
    if not webhook_url:
        print("❌ 找不到 Webhook URL")
        return
    
    response = requests.post(webhook_url, json=data)
    print(f"✅ 已傳送至 Power Automate，狀態碼: {response.status_code}")

if __name__ == "__main__":
    results = check_all_sites()
    send_to_power_automate(results)