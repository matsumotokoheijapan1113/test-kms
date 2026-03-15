import os
import json
from datetime import datetime, timezone

import boto3
import psycopg2
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-1")
KMS_ALIAS = os.getenv("KMS_ALIAS", "")
DB_HOST = os.getenv("DB_HOST", "")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "")
DB_SECRET_NAME = os.getenv("DB_SECRET_NAME", "")

kms_client = boto3.client("kms", region_name=AWS_REGION)
secrets_client = boto3.client("secretsmanager", region_name=AWS_REGION)


def get_db_secret(secret_name: str) -> dict:
    response = secrets_client.get_secret_value(SecretId=secret_name)
    secret_string = response["SecretString"]
    return json.loads(secret_string)


@app.get("/")
def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ecs-kms-rds-checker",
        "time": datetime.now(timezone.utc).isoformat()
    }


@app.get("/check")
def check():
    result = {
        "service": "ecs-kms-rds-checker",
        "time": datetime.now(timezone.utc).isoformat(),
        "kms": {},
        "postgres": {}
    }

    # KMS接続確認
    try:
        if not KMS_ALIAS:
            raise ValueError("KMS_ALIAS is not set")

        kms_res = kms_client.describe_key(KeyId=KMS_ALIAS)

        result["kms"] = {
            "status": "ok",
            "key_id": kms_res["KeyMetadata"]["KeyId"],
            "arn": kms_res["KeyMetadata"]["Arn"],
            "key_state": kms_res["KeyMetadata"]["KeyState"],
            "description": kms_res["KeyMetadata"].get("Description", "")
        }

    except Exception as e:
        result["kms"] = {
            "status": "ng",
            "error": str(e)
        }

    # PostgreSQL接続確認
    conn = None
    try:
        if not DB_HOST:
            raise ValueError("DB_HOST is not set")
        if not DB_NAME:
            raise ValueError("DB_NAME is not set")
        if not DB_SECRET_NAME:
            raise ValueError("DB_SECRET_NAME is not set")

        secret = get_db_secret(DB_SECRET_NAME)

        db_user = secret.get("username")
        db_password = secret.get("password")

        if not db_user or not db_password:
            raise ValueError("username or password not found in Secrets Manager secret")

        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=db_user,
            password=db_password,
            connect_timeout=5
        )

        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            version = cur.fetchone()[0]

            cur.execute("SELECT current_database(), current_user;")
            db_info = cur.fetchone()

        result["postgres"] = {
            "status": "ok",
            "database": db_info[0],
            "user": db_info[1],
            "version": version
        }

    except Exception as e:
        result["postgres"] = {
            "status": "ng",
            "error": str(e)
        }

    finally:
        if conn:
            conn.close()

    overall_ok = (
        result["kms"].get("status") == "ok"
        and result["postgres"].get("status") == "ok"
    )

    result["overall_status"] = "ok" if overall_ok else "ng"
    return result