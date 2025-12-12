import os
import logging
from fastapi import FastAPI, Request, Security, HTTPException
from fastapi.security.api_key import APIKeyHeader
from starlette.status import HTTP_401_UNAUTHORIZED

# -----------------------------
# 設定
# -----------------------------
API_KEY_NAME = "X-API-Key"

# 本番では App Service のアプリケーション設定に API_KEY を入れておく
API_KEY = os.getenv("API_KEY")
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# ロギング設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = FastAPI()


# -----------------------------
# 共通: クライアントIPを取得する関数
# -----------------------------
def get_client_ip(request: Request) -> str:
    """
    Azure App Service では X-Forwarded-For の先頭要素がクライアントのグローバルIPになる想定。
    無ければ request.client.host をフォールバック利用。
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # "1.2.3.4, 10.0.0.1" みたいな形式の先頭を使う
        return xff.split(",")[0].strip()
    return request.client.host


# -----------------------------
# 共通: APIキー検証用 dependency
# -----------------------------
async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key is None:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="API Key required",
        )
    if api_key != API_KEY:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key


# -----------------------------
# 認証付きエンドポイントの例
# -----------------------------
@app.get("/")
async def secure_info(
    request: Request,
    api_key: str = Security(get_api_key),  # ここでAPIキー認証を強制
):
    client_ip = get_client_ip(request)

    # ログにIPとパス等を出す
    logger.info(f"Authorized request from IP={client_ip}, path={request.url.path}")

    return {
        "message": "API Key OK & IP logged",
        "client_ip": client_ip,
        "path": str(request.url.path),
    }