FROM python:3.13-alpine

WORKDIR /app

COPY requirements.txt ./
RUN apk add --no-cache --virtual .build-deps build-base libffi-dev openssl-dev \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && rm requirements.txt \
    && apk del .build-deps

COPY . .

CMD ["python", "-m", "src"]
