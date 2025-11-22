import json
import logging
import os
import boto3
import requests

# -----------------------------------------------
# logging
# -----------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ------------------------------------------------------------
# AWS clients /constants
# ------------------------------------------------------------
secrets = boto3.client("secretsmanager")

DEFAULT_ENV = "DEV"
HTTP_TIMEOUT = 5

# ------------------------------------------------------------
# Load environment-specific configuration from Secrets Manager
# ------------------------------------------------------------
def load_env_config(env_name: str) -> dict:
    """
    Load configuration for a specific environment (DEV/QA/PROD, etc)
    from a single Secrets Manager secret.
    Supports both nested and flat secret structures.
    """
    secret_name = os.environ["SNOW_SECRET_NAME"]
    raw = secrets.get_secret_value(SecretId=secret_name)
    secret_json = json.loads(raw["SecretString"])
    # If the secret is nested by environment, use that
    if env_name in secret_json and isinstance(secret_json[env_name], dict):
        logger.info(f"Loaded config for environment: {env_name}")
        return secret_json[env_name]
    # If the secret is flat, just return the whole secret
    logger.info(f"Environment {env_name} not found, using flat secret structure.")
    return secret_json

# -------------------------------------------------------------------
# ServiceNow / Apigee Reader using API Token
# -------------------------------------------------------------------
class SnowStatusReader:
    def __init__(self, env_name: str):
        self.env = env_name
        self.cfg = load_env_config(env_name)
        try:
            self.api_token = self.cfg["api_token"]
            self.apigee_url = self.cfg["create_incident_url"]
        except KeyError as e:
            logger.error(f"Missing required key in config: {e}")
            raise Exception(f"Missing required key in config: {e}")

    # Ticket status
    def get_ticket_status(self, ticket: str) -> str | None:
        url = f"{self.apigee_url}{ticket}?view=summary"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"[{self.env}] Calling ServiceNow: {url}")
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data.get("state")

    # Incident creation
    def create_incident(self) -> str | None:
        payload = {
            "short_description": f"Automatically created by AWS Lambda({self.env})",
            "assignment_group": "CCB_DGT_SENG_PSE",  
        }
        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"[{self.env}] Creating incident in servicenow...")
        resp = requests.post(
            self.apigee_url,  
            json=payload,
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
        return result.get("number")

#---------------------------------------------------------------------------------------
# Lambda handler
#----------------------------------------------------------------------------------------
def handler(event, context):
    logger.info("Incoming event: " + json.dumps(event))

    # Pick environment from event, default to DEV
    env = event.get("environment", DEFAULT_ENV)
    incident = event.get("incident")
    change = event.get("change")
    valid = False
    checked_ticket = None
    status = None

    reader = SnowStatusReader(env)  

    #--------1) Check incident ticket if provided-------------------------------------------
    if incident:
        logger.info(f"[{env}] checking incident: {incident}")
        status = reader.get_ticket_status(incident)  
        if status in ["open", "assigned"]:
            valid = True

    # -------2) If not valid yet, check change ticket -----------------------------------------
    if change and not valid:
        logger.info(f"[{env}] Checking change: {change}")
        status = reader.get_ticket_status(change)
        checked_ticket = change
        if status == "scheduled":
            valid = True

    #---------3) If no valid ticket, create a new incident ---------------------------------------
    if not valid:
        logger.info(f"[{env}] No valid ticket - creating new incident")
        new_inc = reader.create_incident()
        return {
            "status": "created",
            "environment": env,
            "incident": new_inc,
        }

    #---------4) Valid ticket found ------------------------------------------------------------------
    return {
        "status": "validated",
        "environment": env,
        "ticket": checked_ticket,  
        "ticket_status": status,   
    }
