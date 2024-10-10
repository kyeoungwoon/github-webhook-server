# About

GitHub Repository에 발생한 변경사항들을 Telegram을 통해 알람을 받아볼 수 있습니다.

## Requirements

- Docker 실행환경
- Telegram Bot Token & 알람을 받을 채팅방의 Chat ID
- Repository에서 Webhook 설정을 해주어야 합니다.

## How to

0. 알람을 받고자 하는 GitHub Repository에 들어갑니다.

   - **Settings** > **Webhooks** > **Add webhook**
   - **Payload URL**: 코드를 실행 중인 환경에 접속할 수 있는 방법을 입력합니다.
   - **Content type**: `application/json`
   - **Secret**: 아무거나 상관없지만, 무작위 문자열일수록 보안적인 측면에서 유리합니다.
   - **SSL verification**: 이 코드에서는 SSL 인증서를 포함하지 않으므로, 추가로 설정하시지 않았다면 `Disable` 해줍니다.
   - **Which events would you like to trigger this webhook?**: `Send me everything`

1. 프로젝트의 코드가 있는 root directory에 config.json 파일을 추가해주세요.  
    `./config.json`

   ```json
   {
     "GITHUB_WEBHOOK_SECRET": "YOUR SECRET",
     "TELEGRAM_BOT_TOKEN": "YOUR TOKEN",
     "CHAT_ID": "YOUR CHAT ID"
   }
   ```

2. 해당 코드가 있는 Root Directory에서 다음 command를 terminal에서 실행합니다.

   ```shell
   docker compose build --no-cahce
   docker compose up
   ```

## Version History

- **v1.0.0** - _2024/10/10_
  - Initial project release
- **v1.1.0** - _2024/10/11_
  - Merged two `config.json` files into one
  - fixed docker-compose file to mount `config.json` file

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
