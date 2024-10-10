import requests
import json

# config.json 파일 경로
config_file = './config.json'

# JSON 파일 불러오기
with open(config_file, 'r') as file:
    config = json.load(file)

# JSON 데이터에서 필요한 값들 가져오기
TELEGRAM_BOT_TOKEN = config.get('TELEGRAM_BOT_TOKEN')
CHAT_ID = config.get('CHAT_ID')

def send_message(message):
    # 텔레그램 API URL
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    if len(message) > 4096:
        message = "메세지가 너무 깁니다.\n\n" + message[:128]
        
    response = requests.post(url, data={'chat_id': CHAT_ID, 'text': message})

    if response.status_code == 200:
        print('Message sent successfully!')
    else:
        print('Failed to send message.')