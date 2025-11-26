import json
import logging
import os
import boto3
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter, Retry

# --- Logging Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Constants ---
DEFAULT_ENV = "DEV"        # DEV is the default environment
HTTP_TIMEOUT = 5
RETRY_TOTAL = 3
RETRY_BACKOFF = 0.5

# --- AWS Secrets Manager Client ---
secrets_client = boto3.client("secretsmanager")


# --- Utility Functions ---

def is_valid_url(url: str) -> bool:
    """Checks if the provided string is a valid HTTP/HTTPS URL."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def get_secret(secret_name: str) -> dict:
    """Retrieves and parses a secret from AWS Secrets Manager."""
    if not secret_name:
        logger.error("SNOW_SECRET_NAME environment variable is not set.")
        raise ValueError("Missing SNOW_SECRET_NAME environment variable")

    try:
        resp = secrets_client.get_secret_value(SecretId=secret_name)
        secret_str = resp.get("SecretString") or resp.get("SecretBinary", b"").decode(
            "utf-8"
        )
        secret_json = json.loads(secret_str)
        logger.info(f"Successfully retrieved secret: {secret_name}")
        return secret_json
    except Exception as e:
        logger.error(f"Error retrieving or parsing secret: {e}")
        raise RuntimeError("Failed to retrieve or parse secret from Secrets Manager")


def get_env_config(env_name: str, secret_json: dict) -> dict:
    """
    Extracts environment-specific config from secret JSON.

    Supports:
      - Nested: {"DEV": {...}, "UAT": {...}, "PROD": {...}}
      - Flat:   {"client_id": "...", "servicenow_instance_url": "...", ...}
    """
    if env_name in secret_json and isinstance(secret_json[env_name], dict):
        logger.info(f"Loaded nested config for environment: {env_name}")
        return secret_json[env_name]

    logger.info(
        f"Environment {env_name} not found as nested; using flat secret structure."
    )
    return secret_json


def get_requests_session() -> requests.Session:
    """Returns a requests session with retry logic."""
    session = requests.Session()
    retries = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_access_token(cfg: dict, session: requests.Session) -> str:
    """
    Retrieves an access token using credentials from Secrets Manager
    and token URL from Lambda environment variables.

    Secrets config must contain:
      - client_id
      - username
      - password
      - rsrc

    Lambda environment must contain:
      - TOKEN_URL

    Body sent to token URL:
      client_id, username, password, rsrc
    """
    required_keys = ["client_id", "username", "password", "rsrc"]
    missing_keys = [k for k in required_keys if k not in cfg]
    if missing_keys:
        logger.error(
            f"Missing required keys in config for token request: {missing_keys}"
        )
        raise KeyError("Missing required keys for token request")

    # token_url now comes from Lambda env vars, not from the secret JSON
    try:
        token_url = os.environ["TOKEN_URL"]
    except KeyError:
        logger.error("TOKEN_URL environment variable is not set.")
        raise ValueError("Missing TOKEN_URL environment variable")

    data = {
        "client_id": cfg["client_id"],
        "username": cfg["username"],
        "password": cfg["password"],
        "rsrc": cfg["rsrc"],
    }

    logger.info(f"Requesting access token from: {token_url}")
    try:
        resp = session.post(token_url, data=data, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        token = body.get("access_token")
        if not token:
            logger.error(f"No 'access_token' field in token response: {body}")
            raise ValueError("No 'access_token' field in token response")
        logger.info("Successfully obtained access token from Apigee")
        return token
    except Exception as e:
        logger.error(f"Error requesting access token: {e}")
        raise RuntimeError("Failed to request access token")


# --- ServiceNow / Apigee Reader Class ---

class SnowStatusReader:
    """
    Lambda-Apigee-ServiceNow reader.

    - Reads Apigee/SNOW config from Secrets Manager (per env or flat).
    - Uses client_id, username, password, rsrc from secret,
      and token_url from Lambda env (TOKEN_URL) to get a Bearer token.
    - Calls Apigee change/incident API to check status and create tickets.
    """

    def __init__(self, env_name: str):
        # Default to DEV if env is missing or empty
        if not env_name:
            env_name = DEFAULT_ENV

        self.env = env_name

        # 1) Load secret JSON
        secret_name = os.environ.get("SNOW_SECRET_NAME")
        secret_json = get_secret(secret_name)

        # 2) Extract env-specific config (or flat)
        self.cfg = get_env_config(env_name, secret_json)

        # 3) Base URL for Apigee-ServiceNow API (change/incident)
        #    Example for DEV:
        #    https://developer-s2-dev-nam-mitra.jpmchase.net/gti-it-service-mgt/change/v7/changes
        self.base_url = self.cfg.get("servicenow_instance_url", "").rstrip("/")
        if not is_valid_url(self.base_url):
            logger.error(
                f"servicenow_instance_url is not a valid URL for env {env_name}: {self.base_url}"
            )
            raise ValueError("servicenow_instance_url is not a valid URL")

        # 4) HTTP session with retries
        self.session = get_requests_session()

        # 5) Dynamic token from Apigee using client_id, username, password, rsrc
        #    and TOKEN_URL from environment.
        self.api_token = get_access_token(self.cfg, self.session)

    def get_ticket_status(self, ticket: str) -> str:
        """
        Calls Apigee to get the ticket status.

        GET {base_url}/{ticket}?view=summary

        Expects JSON with "state" field.
        """
        url = f"{self.base_url}/{ticket}?view=summary"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"[{self.env}] Calling ServiceNow/Apigee status endpoint: {url}")
        try:
            resp = self.session.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"[{self.env}] Ticket status response: {json.dumps(data)}")

            state = data.get("state")
            if not state:
                logger.error(f"Missing 'state' in ticket response: {data}")
                raise ValueError("Invalid ticket response format")
            return state
        except Exception as e:
            logger.error(f"Error calling ServiceNow status endpoint: {e}")
            raise RuntimeError("Failed to call ServiceNow status endpoint")

    def create_incident(self) -> str:
        """
        Creates a new ticket (incident/change) via Apigee.

        POST {base_url}

        Expects JSON with "number" field.
        """
        env_label = os.getenv("ENVIRONMENT", DEFAULT_ENV)
        assignment_group = os.getenv("INCIDENT_ASSIGN_GROUP", "CCB_DGT_SENG_PSE")

        payload = {
            "short_description": f"Automatically created by AWS Lambda ({env_label})",
            "assignment_group": assignment_group,
        }

        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"[{self.env}] Creating incident via: {self.base_url}")
        logger.info(f"[{self.env}] Incident payload: {json.dumps(payload)}")

        try:
            resp = self.session.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"[{self.env}] Incident creation response: {json.dumps(result)}"
            )

            number = result.get("number")
            if not number:
                logger.error(
                    f"Missing 'number' in incident creation response: {result}"
                )
                raise ValueError("Invalid incident creation response format")
            return number
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            raise RuntimeError("Failed to create incident")


# --- Lambda Handler ---

def handler(event, context):
    """
    Event example:

    {
      "environment": "DEV",         # optional; defaults to DEV
      "incident": "INC1234567",     # optional
      "change": "CHG1234567"        # optional
    }

    Logic:
      1) If incident provided:
           - Check status
           - If "open" or "assigned" => validated
      2) Else if change provided:
           - Check status
           - If "scheduled" => validated
      3) If not valid => create new incident/change via Apigee.
    """
    logger.info("Incoming event: " + json.dumps(event))

    env = event.get("environment", DEFAULT_ENV)
    incident = event.get("incident")
    change = event.get("change")
    valid = False
    checked_ticket = None
    status = None

    try:
        reader = SnowStatusReader(env)
    except Exception as e:
        logger.exception(f"Failed to initialize SnowStatusReader: {e}")
        return {
            "status": "error",
            "environment": env,
            "message": "Failed to initialize ServiceNow/Apigee reader",
            "error": str(e),
        }

    # 1) Check incident ticket
    if incident:
        logger.info(f"[{env}] Checking incident: {incident}")
        try:
            status = reader.get_ticket_status(incident)
            checked_ticket = incident
            if status in ["open", "assigned"]:
                valid = True
        except Exception as e:
            logger.exception(f"[{env}] Error while checking incident {incident}: {e}")

    # 2) Check change ticket if incident not valid
    if change and not valid:
        logger.info(f"[{env}] Checking change: {change}")
        try:
            status = reader.get_ticket_status(change)
            checked_ticket = change
            if status == "scheduled":
                valid = True
        except Exception as e:
            logger.exception(f"[{env}] Error while checking change {change}: {e}")

    # 3) Create new ticket if no valid one
    if not valid:
        logger.info(f"[{env}] No valid ticket - creating new incident/change")
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

    # 4) Valid ticket found
    return {
        "status": "validated",
        "environment": env,
        "ticket": checked_ticket,
        "ticket_status": status,
    }
