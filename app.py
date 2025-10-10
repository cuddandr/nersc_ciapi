import logging
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s", level=logging.INFO)

import hashlib, hmac
import json, yaml
import os
from datetime import datetime
from typing import Dict, Any, Optional, Final

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7523 import PrivateKeyJWT

from litestar import Litestar, post, get, Request, Response
from litestar.datastructures import State
from litestar.logging import LoggingConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.plugins import SwaggerRenderPlugin
from litestar.contrib.jinja import JinjaTemplateEngine
from litestar.template.config import TemplateConfig
from litestar.response import Template
import litestar.status_codes as status_code

from jinja2 import Environment, PackageLoader

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase


class MongoDBService:
    """MongoDB service for webhook storage"""

    def __init__(self, db: AsyncDatabase):
        self.db = db
        self.collection = db.webhooks

    async def store_webhook(
        self, event_type: str, payload: Dict[str, Any], headers: dict[str, str]
    ) -> str:
        """Store a webhook event in MongoDB"""
        document = {
            "event_type": event_type,
            "payload": payload,
            "headers": headers,
            "received_at": datetime.utcnow(),
        }
        result = await self.collection.insert_one(document)
        return str(result.inserted_id)

    async def get_webhooks(self, limit: int = 50, event_type: Optional[str] = None) -> list:
        """Retrieve webhook events from MongoDB"""
        query = {}
        if event_type:
            query["event_type"] = event_type

        cursor = self.collection.find(query).sort("received_at", -1).limit(limit)
        webhooks = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            webhooks.append(doc)
        return webhooks

    async def get_webhook_by_id(self, webhook_id: str) -> Optional[dict]:
        """Retrieve a single webhook by ID"""
        from bson import ObjectId

        try:
            doc = await self.collection.find_one({"_id": ObjectId(webhook_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception:
            return None

    async def get_event_types(self) -> list:
        """Get all unique event types"""
        return await self.collection.distinct("event_type")

    async def get_stats(self) -> dict[str, Any]:
        """Get webhook statistics"""
        total = await self.collection.count_documents({})

        # Get event type counts
        pipeline = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        event_counts = []
        # From PyMongo documentation: pymongo.asynchronous.collection.AsyncCollection.aggregate
        async with await self.collection.aggregate(pipeline) as cursor:
            async for doc in cursor:
                event_counts.append({"event_type": doc["_id"], "count": doc["count"]})

        return {"total_webhooks": total, "event_counts": event_counts}


def read_file_content(file_path: str) -> str:
    """Read content from a file and return as a string."""
    try:
        with open(file_path, "r") as file:
            content = file.read()
            return content
    except Exception as e:
        logging.error(f"Error: {e}")
        return ""


def verify_github_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify that the webhook came from GitHub"""
    if not signature_header or not secret:
        return False

    hash_object = hmac.new(secret.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)


def read_admission_conf(file_path: str) -> dict:
    """Read admission configuration."""
    try:
        with open(file_path, "r") as file:
            logging.info(f"Loading {file_path}")
            yaml_content = yaml.safe_load(file)
            return yaml_content
    except Exception as e:
        logging.error(f"Error: {e}")
        return None


def check_admission(data: dict, admission_conf: dict) -> tuple[bool, dict]:
    return_val = (False, None)

    if admission_conf is None:
        return (True, None)

    if "workflow_job" not in data:
        logging.info("Not admitted, not a workflow job event")
        return return_val

    if data["action"] != "queued":
        logging.info("Not admitted, job not queued")
        return return_val

    if "labels" not in data["workflow_job"]:
        logging.info("Not admitted, no runner label specified")
        return return_val

    for i in admission_conf["repository"]:
        if data["repository"]["full_name"] != i["name"]:
            continue
        elif data["workflow_job"]["head_branch"] not in i["branch"]:
            continue
        elif data["sender"]["login"] not in i["user"].keys():
            continue
        else:
            nersc_user = i["user"][data["sender"]["login"]]
            return_val = (True, {"user": nersc_user, "cluster": i["cluster"]})
            break
    return return_val


def submit_job(data_dict: dict, nersc_dict: dict) -> Final[int]:
    """Run the job."""
    # Implement the job logic here
    logging.info(f"Repository: {data_dict['repository']['full_name']}")
    logging.info(f"Branch: {data_dict['workflow_job']['head_branch']}")
    logging.info(f"Sender: {data_dict['sender']['login']}")
    print(nersc_dict['cluster'])

    client_id = read_file_content(nersc_dict['cluster']['perlmutter']['client_id']).strip()
    private_key = read_file_content(nersc_dict['cluster']['perlmutter']['private_key'])

    logging.info("Running on Perlmutter")
    logging.info(f"CLIENT_ID = {client_id}")
    logging.info(f"TOKEN_URL = {TOKEN_URL}")
    session = OAuth2Session(
        client_id,
        private_key,
        PrivateKeyJWT(TOKEN_URL),
        grant_type="client_credentials",
        token_endpoint=TOKEN_URL,
    )
    session.fetch_token()
    # cmd = f"${{HOME}}/start_runner.sh {data_dict['repository']['full_name']}"
    cmd = f"${{HOME}}/start_runner.sh {nersc_dict['_id']}"
    try:
        # Validate NERSC username
        logging.info(f"Checking NERSC username: {nersc_dict['user']}.")
        r = session.get(f"https://api.nersc.gov/api/v1.2/account?username={nersc_dict['user']}")
        r.raise_for_status()
        logging.info(f"Superfacility API status: {r.json()}")
        logging.info(f"{nersc_dict['user']} valid NERSC user.")

        # Run script on Perlmutter
        r = session.post("https://api.nersc.gov/api/v1.2/utilities/command/perlmutter", data = {"executable": cmd})
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
    # Get the signature from headers
    logging.info("Received hook.")
    signature = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Hub-Signature")
    event_type = request.headers.get("X-GitHub-Event", "unknown")

    if not signature and WEBHOOK_SECRET:
        return Response(
            content={"error": "Missing signature"}, status_code=status_code.HTTP_400_BAD_REQUEST
        )

    # Get raw body for signature verification
    body = await request.body()

    # Verify the webhook signature if secret is configured
    if WEBHOOK_SECRET:
        logging.info("Verifying hook.")
        if not verify_github_signature(body, signature, WEBHOOK_SECRET):
            return Response(
                content={"error": "Invalid signature"},
                status_code=status_code.HTTP_401_UNAUTHORIZED,
            )
        else:
            logging.info("Verification succeeded.")

    # Parse JSON payload
    payload = await request.json()

    logging.info("Storing in MongoDB.")
    # Store in MongoDB
    mongo_service: MongoDBService = state.mongo_service
    webhook_id = await mongo_service.store_webhook(
        event_type=event_type, payload=payload, headers=dict(request.headers)
    )

    logging.info("Checking job admission.")
    permission, nersc_config = check_admission(payload, ADMISSION_CONF)
    if not permission:
        logging.info("Job not admitted")
        return Response(
            content={"error": "Job not admitted."}, status_code=status_code.HTTP_401_UNAUTHORIZED
        )
    logging.info("Job admitted.")
    nersc_config['_id'] = webhook_id
    return_code = submit_job(payload, nersc_config)

    return Response(
        content={"message": "Webhook received", "event_type": event_type, "webhook_id": webhook_id},
        status_code=return_code,
    )


@get("/webhooks")
async def list_webhooks(
    state: State, limit: int = 50, event_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Endpoint to retrieve stored webhooks

    Query parameters:
    - limit: Number of webhooks to return (default: 50)
    - event_type: Filter by GitHub event type (optional)
    """
    mongo_service: MongoDBService = state.mongo_service
    webhooks = await mongo_service.get_webhooks(limit=limit, event_type=event_type)

    return {"count": len(webhooks), "webhooks": webhooks}


@get("/")
async def index(state: State, event_type: Optional[str] = None) -> Template:
    """
    Homepage showing webhook dashboard
    """
    if not hasattr(state, 'mongo_service') or state.mongo_service is None:
        return Template(
            template_name="error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB,
                "error_message": str(state.mongo_error)
            }
        )

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
            },
        )
    except Exception as e:
        return Template(
            template_name="error.html",
            context={
                "error_type": "MongoDB Error",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB,
                "error_message": str(e)
            }
        )


@get("/webhooks/{webhook_id:str}")
async def webhook_detail(state: State, webhook_id: str) -> Template:
    """
    Detailed view of a single webhook
    """
    mongo_service: MongoDBService = state.mongo_service
    webhook = await mongo_service.get_webhook_by_id(webhook_id)

    return Template(
        template_name="webhook_details.html",
        context={
            "webhook": webhook,
            "webhook_id": webhook_id,
        },
    )


async def on_startup(app: Litestar) -> None:
    """Initialize MongoDB connection on startup"""
    logging.info("Starting GitHub Webhook Receiver...")
    logging.info(f"MongoDB: {MONGODB_URL}/{MONGODB_DB}")
    logging.info(f"Mongo user: {MONGODB_USER}")
    logging.info(
        f"Webhook Secret: {'Configured' if WEBHOOK_SECRET else 'Not configured (signatures will not be verified)'}"
    )
    client = AsyncMongoClient(MONGODB_URL,
                              username=MONGODB_USER,
                              password=MONGODB_PASS,
                              serverSelectionTimeoutMS=15000)
    try:
        await client.admin.command('ping')
        db = client[MONGODB_DB]
        app.state.mongo_service = MongoDBService(db)
        logging.info(f"Connected to MongoDB: {MONGODB_URL}/{MONGODB_DB}")
    except Exception as e:
        app.state.mongo_service = None
        app.state.mongo_error = e
        logging.error(f"Error pinging MongoDB server: {e}")



async def on_shutdown(app: Litestar) -> None:
    """Close MongoDB connection on shutdown"""
    logging.info("Application shutting down")


# Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
MONGODB_DB = os.getenv("MONGODB_DB", "github_webhooks")
MONGODB_USER = os.getenv("MONGODB_USER", "")
MONGODB_PASS = os.getenv("MONGODB_PASS", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
TOKEN_URL = os.environ.get("TOKEN_URL", "https://oidc.nersc.gov/c2id/token")
ADMISSION_CONF_FILE = os.environ.get("ADMISSION_CONF_FILE", "configs/admission.yaml")
ADMISSION_CONF = read_admission_conf(ADMISSION_CONF_FILE)
JINJA_ENV = Environment(loader=PackageLoader("app"), enable_async=False)
LITESTAR_LOG_CONF = LoggingConfig(
    root = {"level" : "INFO", "handlers": ["queue_listener"]},
    formatters = {
        "standard" : { "format" : "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" }
    },
    log_exceptions="always",
)

app = Litestar(
    route_handlers=[receive_webhook, list_webhooks, index, webhook_detail],
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
)

if __name__ == "__main__":
    app.run()
