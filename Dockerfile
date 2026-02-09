FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir flask pyyaml

COPY app.py .
COPY templates/ templates/

# Default config — mount your own config.yaml at runtime
# 默认配置 — 运行时请挂载你自己的 config.yaml
COPY config.yaml .

EXPOSE 5100

CMD ["python", "app.py"]
