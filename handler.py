import json
import logging
import os

import boto3
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets_client = boto3.client("secretsmanager")

DEFAULT_ENV = "DEV"
HTTP_TIMEOUT = 5


def load_env_config(env_name: str) -> dict:
    secret_name = os.environ["SNOW_SECRET_NAME"]
    logger.info(f"Loading secret from Secrets Manager: {secret_name}")

    resp = secrets_client.get_secret_value(SecretId=secret_name)

    if "SecretString" in resp:
        secret_str = resp["SecretString"]
    else:
        secret_str = resp["SecretBinary"].decode("utf-8")

    secret_json = json.loads(secret_str)

    if env_name in secret_json and isinstance(secret_json[env_name], dict):
        logger.info(f"Loaded nested config for environment: {env_name}")
        return secret_json[env_name]

    logger.info(
        f"Environment {env_name} not found as nested; using flat secret structure."
    )
    return secret_json


def get_access_token(cfg: dict) -> str:
    """
    Use Bruno-style body:
      client_id, grant_type, username, password
    Token URL is passed via env var TOKEN_URL (from Terraform).
    """
    try:
        client_id = cfg["client_id"]
        username = cfg["username"]
        password = cfg["password"]
        grant_type = cfg["grant_type"]
    except KeyError as e:
        logger.error(f"Missing required key in secret JSON for token request: {e}")
        raise Exception(f"Missing required key for token request: {e}")

    token_url = os.environ["TOKEN_URL"]  # 👈 from Terraform env var
    data = {
        "client_id": client_id,
        "username": username,
        "password": password,
        "grant_type": grant_type,
    }

    logger.info(f"Requesting access token from: {token_url}")
    resp = requests.post(token_url, data=data, timeout=HTTP_TIMEOUT)
    logger.info(f"Token endpoint status: {resp.status_code}")
    resp.raise_for_status()

    body = resp.json()
    logger.info(f"Token endpoint response keys: {list(body.keys())}")

    token = body.get("access_token")
    if not token:
        raise Exception("No 'access_token' field in token response")

    return token


class SnowStatusReader:
    def __init__(self, env_name: str):
        self.env = env_name
        self.cfg = load_env_config(env_name)

        try:
            self.base_url = self.cfg["servicenow_instance_url"].rstrip("/")
        except KeyError as e:
            logger.error(f"Missing required key in secret JSON: {e}")
            raise Exception(f"Missing required key in config: {e}")

        self.api_token = get_access_token(self.cfg)

    def get_ticket_status(self, ticket: str):
        url = f"{self.base_url}/{ticket}?view=summary"
        headers = {"Authorization": f"Bearer {self.api_token}"}

        logger.info(f"[{self.env}] Calling ServiceNow status endpoint: {url}")
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()

        data = resp.json()
        logger.info(f"[{self.env}] Ticket status response: {json.dumps(data)}")

        return data.get("state")

    def create_incident(self):
        assignment_group = os.getenv("INCIDENT_ASSIGN_GROUP", "CCB_DGT_SENG_PSE")

        payload = {
            "short_description": f"Automatically created by AWS Lambda ({self.env})",
            "assignment_group": assignment_group,
        }
        headers = {"Authorization": f"Bearer {self.api_token}"}

        logger.info(f"[{self.env}] Creating incident via: {self.base_url}")
        logger.info(f"[{self.env}] Incident payload: {json.dumps(payload)}")

        resp = requests.post(
            self.base_url,
            json=payload,
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()

        result = resp.json()
        logger.info(f"[{self.env}] Incident creation response: {json.dumps(result)}")

        return result.get("number")


def handler(event, context):
    logger.info("Incoming event: " + json.dumps(event))

    env = event.get("environment", DEFAULT_ENV)
    incident = event.get("incident")
    change = event.get("change")

    valid = False
    checked_ticket = None
    status = None

    reader = SnowStatusReader(env)

    if incident:
        logger.info(f"[{env}] Checking incident: {incident}")
        try:
            status = reader.get_ticket_status(incident)
            checked_ticket = incident
            if status in ["open", "assigned"]:
                valid = True
        except Exception as e:
            logger.exception(f"[{env}] Error while checking incident {incident}: {e}")

    if change and not valid:
        logger.info(f"[{env}] Checking change: {change}")
        try:
            status = reader.get_ticket_status(change)
            checked_ticket = change
            if status == "scheduled":
                valid = True
        except Exception as e:
            logger.exception(f"[{env}] Error while checking change {change}: {e}")

    if not valid:
        logger.info(f"[{env}] No valid ticket - creating new incident")
        try:
            new_inc = reader.create_incident()
            return {
                "status": "created",
                "environment": env,
                "incident": new_inc,
            }
        except Exception as e:
            logger.exception(f"[{env}] Failed to create incident: {e}")
            return {
                "status": "error",
                "environment": env,
                "message": "Failed to create incident",
                "error": str(e),
            }

    return {
        "status": "validated",
        "environment": env,
        "ticket": checked_ticket,
        "ticket_status": status,
    }

