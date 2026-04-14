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
    
    # 🌟 增加偽裝瀏覽器的 Header
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    for site in SITES:
        try:
            # 🌟 將 timeout 增加到 25 秒，並加入 headers
            res = requests.get(site['url'], timeout=25, headers=headers)
            
            if res.status_code == 200:
                if site['key'] in res.text:
                    status = "🟢 正常"
                else:
                    status = "🟡 內容異常 (關鍵字缺失)"
                    has_error = True
            else:
                status = f"🔴 錯誤 (代碼: {res.status_code})"
                has_error = True
        except requests.exceptions.Timeout:
            status = "⏳ 逾時 (國外連線過慢)"
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

    # 🌟 關鍵修正：配合你 Power Automate 的欄位名稱 "message"
    payload = {
        "message": f"### {data['title']}\n\n{data['status_report']}"
    }
    
    try:
        response = requests.post(
            webhook_url, 
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        print(f"✅ 已傳送至 Power Automate，狀態碼: {response.status_code}")
    except Exception as e:
        print(f"💥 發送失敗: {e}")

if __name__ == "__main__":
    results = check_all_sites()
    send_to_power_automate(results)
