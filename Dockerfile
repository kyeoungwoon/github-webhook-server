# 베이스 이미지로 Python 사용
FROM python:3.12

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 복사 및 패키지 설치
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 복사
COPY . .

# Gunicorn으로 애플리케이션 실행
CMD ["gunicorn", "-b", "0.0.0.0:10002", "app:app"]