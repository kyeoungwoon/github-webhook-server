import hmac
import hashlib
import json
from flask import Flask, request, abort, jsonify
from ipaddress import ip_address, ip_network
import logging
import os

from telegram_bot.main import send_message

# 로그 파일 저장 경로
log_directory = 'logs'
log_file = 'app.log'

# 로그 디렉토리가 없으면 생성
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# 로그 파일의 전체 경로
log_path = os.path.join(log_directory, log_file)

# 로깅 설정
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(log_path)])

app = Flask(__name__)

# Webhook Secret 설정 (GitHub Webhook 설정에 넣은 값)
# config.json 파일에서 Webhook Secret을 가져옵니다.
with open('config.json') as config_file:
    config = json.load(config_file)
    WEBHOOK_SECRET = config.get('GITHUB_WEBHOOK_SECRET')

with open('github_ip.json') as github_ip_file:
    github_ip = json.load(github_ip_file)
    HOOK_IP_LIST = github_ip.get('hooks')

def is_valid_ip(req):
    """
    요청의 IP가 GitHub의 IP 목록에 포함되는지 확인합니다.
    """
    # 요청의 IP 주소를 가져옵니다.
    request_ip = ip_address(request.remote_addr)
    app.logger.info(f'Request IP: {request_ip}')
    
    # GitHub IP 목록을 순회하며 요청 IP가 포함되는지 확인합니다.
    for cidr in HOOK_IP_LIST:
        if request_ip in ip_network(cidr):
            return True
    return False

def is_valid_signature(req):
    """
    GitHub 서명 검증 함수.
    GitHub에서 전송된 서명이 유효한지 확인합니다.
    """
    # GitHub로부터 전송된 X-Hub-Signature-256 헤더를 가져옵니다.
    signature = req.headers.get('X-Hub-Signature-256')
    
    if signature is None:
        return False

    # GitHub 서명은 'sha256='으로 시작합니다.
    sha_name, signature = signature.split('=') # parse
    if sha_name != 'sha256':
        return False

    # Secret을 사용해 HMAC-SHA256으로 요청 본문을 해싱합니다.
    hash_object = hmac.new(WEBHOOK_SECRET.encode('utf-8'), msg=req.data, digestmod=hashlib.sha256)
    
    # 계산된 해시 값과 GitHub로부터 받은 서명을 비교합니다.
    result = hmac.compare_digest(hash_object.hexdigest(), signature)
    app.logger.info(f'Signature is valid: {result}')

    return result

@app.before_request
def limit_remote_addr():
    if not is_valid_ip(request):
        app.logger.error('Forbidden: IP not allowed')
        abort(403, 'Forbidden: IP not allowed')
    
@app.route('/webhook', methods=['POST'])
def github_webhook():
    if request.method == 'POST':
        # 요청의 서명을 검증합니다.
        if not is_valid_signature(request):
            app.logger.error('Invalid signature')
            abort(400, 'Invalid signature')
        
        # GitHub 이벤트 타입을 가져옵니다.
        event_type = request.headers.get('X-GitHub-Event')
        
        if event_type is None:
            app.logger.error('Missing X-GitHub-Event header')
            abort(400, 'Missing X-GitHub-Event header')
        
        # 이벤트 타입에 따라 처리합니다.
        if event_type == 'push':
            # push 이벤트 처리
            payload = request.json
            ref = payload.get('ref')
            commits_message = payload.get('commits').get('message')
            commits_username = payload.get('commits').get('username')
            commits_timestamp = payload.get('commits').get('timestamp')
            pusher = payload.get('pusher', [])

            message = (
                f"[event_type : {event_type}]\n"
                f"[pusher : {pusher}] pushed to [ref : {ref}]\n"
                f"commit message : {commits_message}\n"
                f"user name : {commits_username}\n"
                f"time : {commits_timestamp}"
            )
            send_message(message)

            return jsonify({'type': event_type}), 200
        
        elif event_type == 'pull_request':
            # pull_request 이벤트 처리
            payload = request.json
            action = payload.get('action')
            pr = payload.get('pull_request')
            pr_title = pr.get('title')
            pr_user = pr.get('user').get('login')
            pr_body = pr.get('body')
            pr_created_at = pr.get('created_at')
            pr_updated_at = pr.get('updated_at')
            pr_assignees = ', '.join([assignee.get('login') for assignee in pr.get('assignees', [])])
            pr_requested_reviewers = ', '.join([reviewer.get('login') for reviewer in pr.get('requested_reviewers', [])])
            sender = payload.get('sender').get('login')

            message = (
                f"[event_type : {event_type}]\n"
                f"[sender : {sender}] [action : {action}]\n"
                f"Pull Request:\n"
                f"  Title       : {pr_title}\n"
                f"  User        : {pr_user}\n"
                f"  Body        : {pr_body}\n"
                f"  Created At  : {pr_created_at}\n"
                f"  Updated At  : {pr_updated_at}\n"
                f"  Assignees   : {pr_assignees}\n"
                f"  Reviewers   : {pr_requested_reviewers}"
            )
            send_message(message)

            return jsonify({'type': event_type}), 200
    
        elif event_type == 'create':
            # create 이벤트 처리 (브랜치 생성 등)
            payload = request.json
            sender = payload.get('sender').get('login')
            ref = payload.get('ref')
            ref_type = payload.get('ref_type')

            message = (
                f"[event_type : {event_type}]\n"
                f"[sender : {sender}] created\n"
                f"  Ref Type : {ref_type}\n"
                f"  Ref      : {ref}"
            )
            send_message(message)

            return jsonify({'type': event_type}), 200
        
        elif event_type == 'ping':
            send_message('Ping event received')

            return jsonify({'type': event_type}), 200
        
        elif event_type == 'issues':
            payload = request.json
            action = payload.get('action')
            issue_title = payload.get('issue').get('title')
            issue_body = payload.get('issue').get('body')
            issue_user = payload.get('issue').get('user').get('login')
            issue_created_at = payload.get('issue').get('created_at')
            issue_updated_at = payload.get('issue').get('updated_at')
            issue_closed_at = payload.get('issue').get('closed_at')
            sender = payload.get('sender').get('login')

            message = (
                f"[event_type : {event_type}]\n"
                f"[sender : {sender}] [action : {action}]\n"
                f"Issue:\n"
                f"  Title       : {issue_title}\n"
                f"  User        : {issue_user}\n"
                f"  Body        : {issue_body}\n"
                f"  Created At  : {issue_created_at}\n"
                f"  Updated At  : {issue_updated_at}\n"
                f"  Closed At   : {issue_closed_at}"
            )
            send_message(message)

            return jsonify({'type': event_type}), 200
        
        elif event_type == 'issue_comment':
            payload = request.json
            action = payload.get('action')
            issue_title = payload.get('issue').get('title')
            issue_body = payload.get('issue').get('body')
            issue_user = payload.get('issue').get('user').get('login')
            issue_created_at = payload.get('issue').get('created_at')
            issue_updated_at = payload.get('issue').get('updated_at')
            issue_closed_at = payload.get('issue').get('closed_at')
            comment_body = payload.get('comment').get('body')
            comment_user = payload.get('comment').get('user').get('login')
            comment_created_at = payload.get('comment').get('created_at')
            sender = payload.get('sender').get('login')

            message = (
                f"[event_type : {event_type}]\n"
                f"[sender : {sender}] [action : {action}]\n"
                f"Comment:\n"
                f"  Issue Title : {issue_title}\n"
                f"  Issue User  : {issue_user}\n"
                f"  Issue Body  : {issue_body}\n"
                f"  Created At  : {issue_created_at}\n"
                f"  Updated At  : {issue_updated_at}\n"
                f"  Closed At   : {issue_closed_at}\n\n"
                f"  Comment     : {comment_body}\n"
                f"  Comment User: {comment_user}\n"
                f"  Comment Time: {comment_created_at}"
            )
            send_message(message)

            return jsonify({'type': event_type}), 200

        else:
            # 처리하지 않는 이벤트 타입
            message = f'처리되지 않는 이벤트 타입입니다\n[event_type] {event_type}'
            send_message(message)

            return jsonify({'type': event_type}), 200
        
# app.run(port=8080, debug=True)
