import logging

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s", level=logging.INFO
)

import hashlib, hmac
import ipaddress
from typing import Any, Optional

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7523 import PrivateKeyJWT

from litestar import Litestar, post, get, Request, Response, MediaType
from litestar.datastructures import State
from litestar.logging import LoggingConfig
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.plugins import SwaggerRenderPlugin
from litestar.contrib.jinja import JinjaTemplateEngine
from litestar.template.config import TemplateConfig
from litestar.response import Template
from litestar.static_files import create_static_files_router
from litestar.exceptions import NotFoundException, HTTPException, NotAuthorizedException
import litestar.status_codes as status_code

from jinja2 import Environment, PackageLoader

from auth import auth_router, require_login, session_user_context
from profiles import profiles_router
from config import config
from mongodb import MongoDBService, on_startup, on_shutdown
from slurm_queue import queue_router
from utils import read_file_content


def is_ip_authorized(ip: str, cidr_ranges: list[str]) -> bool:
    """Check if an IP address falls within any of the authorized CIDR ranges."""
    logging.info(f"Client IP: {ip}")
    logging.info(f"Checking the following IP ranges: {cidr_ranges}")
    try:
        client_ip = ipaddress.ip_address(ip)
        return any(
            client_ip in ipaddress.ip_network(cidr, strict=False)
            for cidr in cidr_ranges
        ) # returns true if any iterable evaluates to 'truthy'
    except ValueError:
        return False


def verify_github_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify that the webhook came from GitHub"""
    logging.info("Verifying hook signature.")
    if not signature_header or not secret:
        return False

    hash_object = hmac.new(secret.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    logging.info(f"Calc hash: {expected_signature}")
    logging.info(f"Hook hash: {signature_header}")
    return hmac.compare_digest(expected_signature, signature_header)


def check_admission(data: dict, admission_conf: dict) -> tuple[bool, Optional[dict]]:
    if admission_conf is None:
        return (True, None)

    cluster = admission_conf["clusters"][config.hpc.cluster]
    return_val = (False, None)

    if "workflow_job" not in data:
        logging.info("Not admitted, not a workflow job event")
        return return_val

    if data["action"] != "queued":
        logging.info("Not admitted, job action is not queued")
        return return_val

    if "labels" not in data["workflow_job"]:
        logging.info("Not admitted, no runner label specified")
        return return_val

    if data["sender"]["login"] not in cluster["users"]:
        logging.info("Not admitted, not an approved user.")
        return return_val

    for i in admission_conf["repository"]:
        if data["repository"]["full_name"] != i["name"]:
            continue
        elif data["workflow_job"]["head_branch"] not in i["branches"]:
            continue
        else:
            nersc_user = cluster["users"][data["sender"]["login"]]
            return_val = (True, {"user": nersc_user})
            break
    return return_val


def submit_job(data_dict: dict, nersc_dict: dict, admission_conf: dict) -> int:
    """Run the job."""
    cluster = admission_conf["clusters"][config.hpc.cluster]
    logging.info(f"Repository: {data_dict['repository']['full_name']}")
    logging.info(f"Branch: {data_dict['workflow_job']['head_branch']}")
    logging.info(f"Sender: {data_dict['sender']['login']}")

    # Read API secrets from files
    client_id = read_file_content(cluster["client_id"]).strip() # Remove any trailing whitespace
    private_key = read_file_content(cluster["private_key"])

    # Authenticate session for SF-API
    logging.info(f"Running on {config.hpc.cluster} as {cluster['account']}")
    logging.info(f"CLIENT_ID = {client_id}")
    logging.info(f"TOKEN_URL = {config.hpc.token_url}")
    session = OAuth2Session(
        client_id,
        private_key,
        PrivateKeyJWT(config.hpc.token_url),
        grant_type="client_credentials",
        token_endpoint=config.hpc.token_url,
    )
    session.fetch_token()
    # Build command to start runner
    dir = cluster["target_dir"]
    cmd = f"cd {dir}; {dir}/scripts/start_runner.sh {nersc_dict['_id']}"
    try:
        # Validate NERSC username
        logging.info(f"Checking NERSC username: {nersc_dict['user']}.")
        r = session.get(f"https://api.nersc.gov/api/v1.2/account?username={nersc_dict['user']}")
        r.raise_for_status()
        logging.info(f"Superfacility API status: {r.json()}")
        logging.info(f"{nersc_dict['user']} valid NERSC user.")

        # Run script on Perlmutter
        logging.info(f"Submittig task via Superfacility API.")
        r = session.post(
            "https://api.nersc.gov/api/v1.2/utilities/command/perlmutter", data={"executable": cmd}
        )
        r.raise_for_status()
        logging.info(f"Superfacility API status: {r.json()}")
        logging.info("Job submitted.")
        return status_code.HTTP_201_CREATED
    except Exception as e:
        logging.error(f"An error occurred accessing SF API: {e}")
        return e.response.status_code


@post("/webhooks")
async def receive_webhook(
    request: Request,
    state: State,
) -> Response:
    """
    Endpoint to receive GitHub webhooks

    GitHub will send POST requests to this endpoint with webhook payloads
    """
    logging.info("Received hook.")
    # Get the signature and event type from headers
    signature = request.headers.get("X-Hub-Signature-256")
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    # Attempt to grab the original IP address the webhook came from
    client_host = request.headers.get("X-Forwarded-For", request.client.host)
    # X-Forwarded-For can be a comma-separated list; the first entry is the original client
    client_host = client_host.split(",")[0].strip()

    admission_conf = state.admission_conf
    if config.webhook.verify_ip and not is_ip_authorized(
        client_host, admission_conf["ip_range"]
    ):
        logging.info(f"Invalid client IP: {client_host}")
        return Response(
            content={"error": "Invalid client IP"}, status_code=status_code.HTTP_400_BAD_REQUEST
        )

    if not signature and config.webhook.secret:
        logging.info(f"Missing signature.")
        return Response(
            content={"error": "Missing signature"}, status_code=status_code.HTTP_400_BAD_REQUEST
        )

    # Get raw body for signature verification
    body = await request.body()
    # Get json payload for the actual webhook info
    payload = await request.json()

    # Verify the webhook signature if secret is configured
    if config.webhook.secret:
        if not verify_github_signature(body, signature, config.webhook.secret):
            logging.info("Invalid signature.")
            return Response(
                content={"error": "Invalid signature"},
                status_code=status_code.HTTP_401_UNAUTHORIZED,
            )
        else:
            logging.info("Verification succeeded.")

    logging.info("Storing in MongoDB.")
    mongo_service: MongoDBService = state.mongo_service
    webhook_id = await mongo_service.store_webhook(
        event_type=event_type, payload=payload, headers=dict(request.headers)
    )

    logging.info("Checking job admission.")
    permission, nersc_config = check_admission(payload, admission_conf)
    if not permission:
        logging.info("Job not admitted.")
        return Response(
            content={"error": "Job not admitted"}, status_code=status_code.HTTP_401_UNAUTHORIZED
        )
    logging.info("Job admitted.")
    nersc_config["_id"] = webhook_id
    return_code = submit_job(payload, nersc_config, admission_conf)

    return Response(
        content={"message": "Webhook received", "event_type": event_type, "webhook_id": webhook_id},
        status_code=return_code,
    )


@get("/webhooks", guards=[require_login])
async def list_webhooks(
    state: State, limit: int = 10, event_type: Optional[str] = None
) -> dict[str, Any]:
    """
    Endpoint to retrieve stored webhooks

    Query parameters:
    - limit: Number of webhooks to return (default: 10)
    - event_type: Filter by GitHub event type (optional)
    """
    mongo_service: MongoDBService = state.mongo_service

    try:
        webhooks = await mongo_service.get_webhooks(limit=limit, event_type=event_type)
    except Exception as e:
        logging.error(f"Error pinging MongoDB server: {e}")
        return {"count": 0, "webhooks": None}

    return {"count": len(webhooks), "webhooks": webhooks}


@get("/", guards=[require_login])
async def index(request: Request, state: State, event_type: Optional[str] = None) -> Template:
    """
    Homepage showing webhook dashboard
    """
    # Check if connection established to MongoDB and show error page if not
    if not hasattr(state, "mongo_service") or state.mongo_service is None:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": config.mongodb.url,
                "mongodb_db": config.mongodb.db,
                "error_message": str(state.mongo_error),
                "request": request,
                **session_user_context(request),
            },
        )

    # Display the webhook dashboard
    try:
        mongo_service: MongoDBService = state.mongo_service
        webhooks = await mongo_service.get_webhooks(limit=100, event_type=event_type)
        event_types = await mongo_service.get_event_types()
        stats = await mongo_service.get_stats()

        return Template(
            template_name="index.html",
            context={
                "webhooks": webhooks,
                "event_types": event_types,
                "stats": stats,
                "selected_event_type": event_type,
                "request": request,
                **session_user_context(request),
            },
        )
    except Exception as e:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Error",
                "mongodb_url": config.mongodb.url,
                "mongodb_db": config.mongodb.db,
                "error_message": str(e),
                "request": request,
                **session_user_context(request),
            },
        )


@get("/webhooks/{webhook_id:str}", guards=[require_login])
async def webhook_detail(request: Request, state: State, webhook_id: str) -> Template:
    """
    Detailed view of a single webhook
    """
    mongo_service: MongoDBService = state.mongo_service
    webhook = await mongo_service.get_webhook_by_id(webhook_id)
    if not webhook:
        return Template(
            template_name="http_error.html",
            context={
                "status_code": 404,
                "error_title": "Webhook Not Found",
                "error_message": "The webhook you're looking for doesn't exist.",
                "request_path": f"/webhook/{webhook_id}",
                "request": request,
                **session_user_context(request),
            },
            status_code=404
        )

    return Template(
        template_name="webhook_details.html",
        context={
            "request": request,
            "webhook": webhook,
            "webhook_id": webhook_id,
            **session_user_context(request),
        },
    )


def http_exception_handler(request: Request, exc: Exception) -> Response:
    """
    Custom exception handler for HTTP errors
    """
    provided_types = [MediaType.HTML, MediaType.JSON]
    preferred_type = request.accept.best_match(provided_types, default=MediaType.JSON)

    # Unauthenticated/expired-session access to a page: send browsers back
    # through the Globus login flow instead of showing a bare error page.
    # Data endpoints hit via fetch/XHR (JSON) just get a 401 back.
    if isinstance(exc, NotAuthorizedException) and preferred_type == MediaType.HTML:
        from litestar.response import Redirect
        from urllib.parse import urlencode

        next_url = f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path
        return Redirect(f"/auth/login?{urlencode({'next': next_url})}")

    resp_status_code = 500
    error_title = "Internal Server Error"
    error_message = "An unexpected error occurred."

    if isinstance(exc, NotFoundException):
        resp_status_code = 404
        error_title = "Page Not Found"
        error_message = "The page you're looking for doesn't exist."
    elif isinstance(exc, NotAuthorizedException):
        resp_status_code = 401
        error_title = "Unauthorized"
        error_message = exc.detail or "Login required."
    elif isinstance(exc, HTTPException):
        resp_status_code = exc.status_code
        error_title = f"Error {resp_status_code}"
        error_message = exc.detail or "An error occurred."

    # Return HTML or JSON based on request header
    if preferred_type == MediaType.HTML:
        return Template(
            template_name="http_error.html",
            context={
                "status_code": resp_status_code,
                "error_title": error_title,
                "error_message": error_message,
                "request_path": request.url.path,
                "request": request,
                **session_user_context(request),
            },
            status_code=resp_status_code,
        )
    else:
        return Response(
            content={"error": error_title, "message": error_message, "status_code": resp_status_code},
            status_code=resp_status_code,
        )


JINJA_ENV = Environment(loader=PackageLoader("app"), enable_async=False)
LITESTAR_LOG_CONF = LoggingConfig(
    root={"level": "INFO", "handlers": ["queue_listener"]},
    formatters={"standard": {"format": "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"}},
    log_exceptions="always",
)

# Session cookie mirrors the guard's max_age_seconds as a belt-and-suspenders
# measure: the browser stops sending the cookie at the same point the server
# would reject it anyway.
SESSION_CONFIG = CookieBackendConfig(
    secret=config.session.secret,
    max_age=config.session.max_age_seconds,
)

app = Litestar(
    route_handlers=[
        receive_webhook,  # POST /webhooks — GitHub webhook, intentionally unauthenticated
        list_webhooks,
        index,
        webhook_detail,
        create_static_files_router(path="/static", directories=["static"]),
        auth_router,  # /auth/login, /auth/callback, /auth/logout
        profiles_router,  # /profiles, /profile/{id}
        queue_router,  # /queue, /queue-data
    ],
    on_startup=[on_startup],
    on_shutdown=[on_shutdown],
    openapi_config=OpenAPIConfig(
        title="GH Webhooks",
        description="Collecting webhooks",
        version="0.0.1",
        path="/docs",
        render_plugins=[SwaggerRenderPlugin()],
    ),
    template_config=TemplateConfig(
        engine=JinjaTemplateEngine.from_environment(JINJA_ENV),
    ),
    logging_config=LITESTAR_LOG_CONF,
    middleware=[SESSION_CONFIG.middleware],
    exception_handlers={
        HTTPException: http_exception_handler,
        NotFoundException: http_exception_handler,
        NotAuthorizedException: http_exception_handler,
    },
)

if __name__ == "__main__":
    app.run()
