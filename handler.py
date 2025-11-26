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
DEFAULT_ENV = "DEV"
HTTP_TIMEOUT = 5
RETRY_TOTAL = 3
RETRY_BACKOFF = 0.5

# --- AWS Secrets Manager Client ---
secrets_client = boto3.client("secretsmanager")

# --- Utility Functions ---

def is_valid_url(url: str) -> bool:
    """Checks if the provided string is a valid HTTP/HTTPS URL."""
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)

def get_secret(secret_name: str) -> dict:
    """Retrieves and parses a secret from AWS Secrets Manager."""
    if not secret_name:
        logger.error("SNOW_SECRET_NAME environment variable is not set.")
        raise ValueError("Missing SNOW_SECRET_NAME environment variable")
    try:
        resp = secrets_client.get_secret_value(SecretId=secret_name)
        secret_str = resp.get("SecretString") or resp.get("SecretBinary", b"").decode("utf-8")
        return json.loads(secret_str)
    except Exception as e:
        logger.error(f"Error retrieving or parsing secret: {e}")
        raise RuntimeError("Failed to retrieve or parse secret from Secrets Manager")

def get_env_config(env_name: str, secret_json: dict) -> dict:
    """Extracts environment-specific config from secret JSON."""
    if env_name in secret_json and isinstance(secret_json[env_name], dict):
        logger.info(f"Loaded nested config for environment: {env_name}")
        return secret_json[env_name]
    logger.info(f"Environment {env_name} not found as nested; using flat secret structure.")
    return secret_json

def get_requests_session() -> requests.Session:
    """Returns a requests session with retry logic."""
    session = requests.Session()
    retries = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_access_token(cfg: dict, session: requests.Session) -> str:
    """Retrieves an access token using credentials and token URL from config."""
    required_keys = ["client_id", "username", "password", "grant_type", "token_url"]
    missing_keys = [k for k in required_keys if k not in cfg]
    if missing_keys:
        logger.error(f"Missing required keys in config for token request: {missing_keys}")
        raise KeyError("Missing required keys for token request")
    data = {k: cfg[k] for k in required_keys if k != "token_url"}
    token_url = cfg["token_url"]
    logger.info(f"Requesting access token from: {token_url}")
    try:
        resp = session.post(token_url, data=data, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        token = body.get("access_token")
        if not token:
            logger.error(f"No 'access_token' field in token response: {body}")
            raise ValueError("No 'access_token' field in token response")
        return token
    except Exception as e:
        logger.error(f"Error requesting access token: {e}")
        raise RuntimeError("Failed to request access token")

# --- ServiceNow Reader Class ---

class SnowStatusReader:
    def __init__(self, env_name: str):
        secret_name = os.environ.get("SNOW_SECRET_NAME")
        secret_json = get_secret(secret_name)
        self.cfg = get_env_config(env_name, secret_json)
        self.base_url = self.cfg.get("servicenow_instance_url", "").rstrip("/")
        if not is_valid_url(self.base_url):
            logger.error(f"servicenow_instance_url is not a valid URL: {self.base_url}")
            raise ValueError("servicenow_instance_url is not a valid URL")
        self.session = get_requests_session()
        self.api_token = get_access_token(self.cfg, self.session)

    def get_ticket_status(self, ticket: str) -> str:
        url = f"{self.base_url}/{ticket}?view=summary"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"Calling ServiceNow status endpoint: {url}")
        try:
            resp = self.session.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Ticket status response: {json.dumps(data)}")
            state = data.get("state")
            if not state:
                logger.error(f"Missing 'state' in ticket response: {data}")
                raise ValueError("Invalid ticket response format")
            return state
        except Exception as e:
            logger.error(f"Error calling ServiceNow status endpoint: {e}")
            raise RuntimeError("Failed to call ServiceNow status endpoint")

    def create_incident(self) -> str:
        assignment_group = os.getenv("INCIDENT_ASSIGN_GROUP", "CCB_DGT_SENG_PSE")
        payload = {
            "short_description": f"Automatically created by AWS Lambda ({os.getenv('ENV', DEFAULT_ENV)})",
            "assignment_group": assignment_group,
        }
        headers = {"Authorization": f"Bearer {self.api_token}"}
        logger.info(f"Creating incident via: {self.base_url}")
        logger.info(f"Incident payload: {json.dumps(payload)}")
        try:
            resp = self.session.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(f"Incident creation response: {json.dumps(result)}")
            number = result.get("number")
            if not number:
                logger.error(f"Missing 'number' in incident creation response: {result}")
                raise ValueError("Invalid incident creation response format")
            return number
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            raise RuntimeError("Failed to create incident")

# --- Lambda Handler ---

def handler(event, context):
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
            "message": "Failed to initialize ServiceNow reader",
            "error": str(e),
        }

    # Check incident ticket
    if incident:
        logger.info(f"Checking incident: {incident}")
        try:
            status = reader.get_ticket_status(incident)
            checked_ticket = incident
            if status in ["open", "assigned"]:
                valid = True
        except Exception as e:
            logger.exception(f"Error while checking incident {incident}: {e}")

    # Check change ticket if incident not valid
    if change and not valid:
        logger.info(f"Checking change: {change}")
        try:
            status = reader.get_ticket_status(change)
            checked_ticket = change
            if status == "scheduled":
                valid = True
        except Exception as e:
            logger.exception(f"Error while checking change {change}: {e}")

    # Create new incident if no valid ticket
    if not valid:
        logger.info("No valid ticket - creating new incident")
        try:
            new_inc = reader.create_incident()
            return {
                "status": "created",
                "environment": env,
                "incident": new_inc,
            }
        except Exception as e:
            logger.exception(f"Failed to create incident: {e}")
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


