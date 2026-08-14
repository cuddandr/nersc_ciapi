import logging

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s", level=logging.INFO
)

import hashlib, hmac
import json, jq, yaml
import os, time
import ipaddress
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Any, Optional

import plotly.graph_objects as go
import plotly.io as pio

from bson import ObjectId
from bson.codec_options import CodecOptions

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

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from auth import auth_router, require_login, get_session_secret, MAX_SESSION_AGE


class MongoDBService:
    """MongoDB service for webhook storage"""

    def __init__(self, db: AsyncDatabase):
        options = CodecOptions(tz_aware=True, tzinfo=ZoneInfo(TZINFO))
        self.db = db
        self.collection = db.get_collection("webhooks", options)
        self.profiles_collection = db.get_collection("nsys_profiles", options)

    async def store_webhook(
        self, event_type: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> str:
        """Store a webhook event in MongoDB"""
        document = {
            "event_type": event_type,
            "payload": payload,
            "headers": headers,
            "received_at": datetime.now(ZoneInfo(TZINFO)),
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

    async def get_profiles(self, limit: int = 10) -> list:
        """Retrieve profiling data from MongoDB"""
        cursor = self.profiles_collection.find({}).sort("timestamp", -1).limit(limit)
        profiles = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            profiles.append(doc)
        return profiles

    async def get_profile_by_id(self, profile_id: str) -> Optional[dict]:
        """Retrieve a single profile by ID"""
        try:
            doc = await self.profiles_collection.find_one({"_id": ObjectId(profile_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception:
            return None


def read_file_content(file_path: str) -> str:
    """Read content from a file and return as a string."""
    try:
        with open(file_path, "r") as file:
            content = file.read()
            return content
    except Exception as e:
        logging.error(f"Error: {e}")
        return ""


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


def read_admission_conf(file_path: str) -> Optional[dict]:
    """Read admission configuration."""
    try:
        with open(file_path, "r") as file:
            logging.info(f"Loading {file_path}")
            yaml_content = yaml.safe_load(file)
            return yaml_content
    except Exception as e:
        logging.error(f"Error: {e}")
        return None


def check_admission(data: dict, admission_conf: dict) -> tuple[bool, Optional[dict]]:
    cluster = admission_conf["clusters"][HPC_CLUSTER]
    return_val = (False, None)

    if admission_conf is None:
        return (True, None)

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


def submit_job(data_dict: dict, nersc_dict: dict) -> int:
    """Run the job."""
    cluster = ADMISSION_CONF["clusters"][HPC_CLUSTER]
    logging.info(f"Repository: {data_dict['repository']['full_name']}")
    logging.info(f"Branch: {data_dict['workflow_job']['head_branch']}")
    logging.info(f"Sender: {data_dict['sender']['login']}")

    # Read API secrets from files
    client_id = read_file_content(cluster["client_id"]).strip() # Remove any trailing whitespace
    private_key = read_file_content(cluster["private_key"])

    # Authenticate session for SF-API
    logging.info(f"Running on {HPC_CLUSTER} as {cluster['account']}")
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


def filter_sacct(data: dict) -> dict:
    jq_filter = """
    .jobs[] | {
    jobid: .job_id,
    jobname: .name,
    account: .account,
    user: .user,
    state: .state.current[0],
    start: .time.start,
    elapsed: .time.elapsed,
    timelimit: (.time.limit.number * 60)
    }
    """

    jobs = jq.all(jq_filter, data)
    for job in jobs:
        job["start"] = datetime.fromtimestamp(job["start"], tz=ZoneInfo(TZINFO)).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )
        job["elapsed"] = str(timedelta(seconds=job["elapsed"]))
        job["timelimit"] = str(timedelta(seconds=job["timelimit"]))

    total_jobs = len(jobs)
    running_jobs = sum(1 for job in jobs if job["state"] == "RUNNING")
    completed_jobs = sum(1 for job in jobs if job["state"] == "COMPLETED")
    failed_jobs = sum(1 for job in jobs if job["state"] == "FAILED")
    pending_jobs = sum(1 for job in jobs if job["state"] == "PENDING")
    timeout_jobs = sum(1 for job in jobs if job["state"] == "TIMEOUT")
    cancelled_jobs = sum(1 for job in jobs if job["state"] == "CANCELLED")

    return {
        "jobs": jobs,
        "total_jobs": total_jobs,
        "running_jobs": running_jobs,
        "completed_jobs": completed_jobs,
        "failed_jobs": failed_jobs,
        "pending_jobs": pending_jobs,
        "timeout_jobs": timeout_jobs,
        "cancelled_jobs": cancelled_jobs,
    }

# cache is in seconds; need to write a custom filter to only cache on successful responses
@get("/queue-data", cache=180, guards=[require_login])
async def get_queue_info(days: int = 1) -> Response:
    wait_time = 15 # seconds to wait in between polling the SF API task
    num_attempts = 4 # total tries to get the data before giving up

    cluster = ADMISSION_CONF["clusters"][HPC_CLUSTER]
    client_id = read_file_content(cluster["client_id"]).strip()
    private_key = read_file_content(cluster["private_key"])

    # Authenticate session for SF-API
    logging.info(f"Running on {HPC_CLUSTER} as {cluster['account']}")
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
    # Build command to get SLURM queue via sacct
    start_date = date.today() - timedelta(days=days)
    cmd = f'bash -c "sacct -a -X -A dune,dune_g --json -S {start_date}"'
    try:
        # Run sacct on Perlmutter
        logging.info(f"Running sacct on {HPC_CLUSTER}")
        r = session.post(
            "https://api.nersc.gov/api/v1.2/utilities/command/perlmutter", data={"executable": cmd}
        )
        r.raise_for_status()
        logging.info(f"Superfacility API status: {r.json()}")
        post_output = r.json()

        # It takes some time to actually run the command on Perlmutter and have the output available
        # Delay the task retrieval and try a finite number of attempts before giving up
        time.sleep(wait_time)
        logging.info("Getting task output.")

        data = {}
        data["jobs"] = []
        http_status_code = status_code.HTTP_504_GATEWAY_TIMEOUT
        for i in range(num_attempts):
            logging.info(f"Attempt {i}")
            r = session.get(f"https://api.nersc.gov/api/v1.2/tasks/{post_output['task_id']}")
            r.raise_for_status()
            get_output = r.json()

            # Extract `sacct` output from the SF API task payload
            if get_output["result"]:
                task_output = json.loads(get_output["result"])
                task_output = json.loads(task_output["output"])
                data["jobs"] = task_output["jobs"]
                http_status_code = status_code.HTTP_200_OK
                break
            else:
                time.sleep(wait_time)

        filtered = filter_sacct(data)
        return Response(
            content=filtered,
            status_code=http_status_code,
        )

    except Exception as e:
        logging.error(f"An error occurred accessing SF API: {e}")
        return Response(content={"error": str(e)}, status_code=status_code.HTTP_400_BAD_REQUEST)


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

    if VERIFY_IP and not is_ip_authorized(client_host, ADMISSION_CONF['ip_range']):
        logging.info(f"Invalid client IP: {client_host}")
        return Response(
            content={"error": "Invalid client IP"}, status_code=status_code.HTTP_400_BAD_REQUEST
        )

    if not signature and WEBHOOK_SECRET:
        logging.info(f"Missing signature.")
        return Response(
            content={"error": "Missing signature"}, status_code=status_code.HTTP_400_BAD_REQUEST
        )

    # Get raw body for signature verification
    body = await request.body()
    # Get json payload for the actual webhook info
    payload = await request.json()

    # Verify the webhook signature if secret is configured
    if WEBHOOK_SECRET:
        webhook_secret = read_file_content(WEBHOOK_SECRET).strip() # Remove any trailing whitespace
        if not verify_github_signature(body, signature, webhook_secret):
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
    permission, nersc_config = check_admission(payload, ADMISSION_CONF) #TODO: Not really necessary to pass the CONF file as it is a global
    if not permission:
        logging.info("Job not admitted.")
        return Response(
            content={"error": "Job not admitted"}, status_code=status_code.HTTP_401_UNAUTHORIZED
        )
    logging.info("Job admitted.")
    nersc_config["_id"] = webhook_id
    return_code = submit_job(payload, nersc_config)

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
async def index(state: State, event_type: Optional[str] = None) -> Template:
    """
    Homepage showing webhook dashboard
    """
    # Check if connection established to MongoDB and show error page if not
    if not hasattr(state, "mongo_service") or state.mongo_service is None:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB,
                "error_message": str(state.mongo_error),
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
            },
        )
    except Exception as e:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Error",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB,
                "error_message": str(e),
            },
        )


@get("/webhooks/{webhook_id:str}", guards=[require_login])
async def webhook_detail(state: State, webhook_id: str) -> Template:
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
                "request_path": f"/webhook/{webhook_id}"
            },
            status_code=404
        )

    return Template(
        template_name="webhook_details.html",
        context={
            "webhook": webhook,
            "webhook_id": webhook_id,
        },
    )


@get("/queue", guards=[require_login])
async def display_queue(state: State, days: int = 1) -> Template:
    """
    Display Perlmutter job queue. Serves an initially empty webpage
    with loading animation. A JS script inside the HTML performs an
    API call to get the queue info and dynamically update the page.
    """
    return Template(
        template_name="slurm_queue.html",
        context={},
    )

@get("/profiles", guards=[require_login])
async def profiles_list(state: State) -> Template:
    """
    Page displaying all profiling runs with stacked bar chart
    """
    # Check if MongoDB is connected
    if not hasattr(state, 'mongo_service') or state.mongo_service is None:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB
            }
        )

    try:
        mongo_service: MongoDBService = state.mongo_service
        profiles = await mongo_service.get_profiles(limit=50)

        # Create stacked bar chart
        chart_html = create_profiles_chart(profiles)

        return Template(
            template_name="profiles.html",
            context={
                "profiles": profiles,
                "chart_html": chart_html
            }
        )
    except Exception as e:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Error",
                "mongodb_url": MONGODB_URL,
                "mongodb_db": MONGODB_DB,
                "error_message": str(e)
            }
        )


@get("/profile/{profile_id:str}", guards=[require_login])
async def profile_detail(state: State, profile_id: str) -> Template:
    """
    Detailed view of a single profile with individual chart
    """
    mongo_service: MongoDBService = state.mongo_service
    profile = await mongo_service.get_profile_by_id(profile_id)

    if not profile:
        return Template(
            template_name="http_error.html",
            context={
                "status_code": 404,
                "error_title": "Profile Not Found",
                "error_message": "The profile you're looking for doesn't exist.",
                "request_path": f"/profile/{profile_id}"
            },
            status_code=404
        )

    # Create individual profile chart
    chart_html = create_single_profile_chart(profile)

    return Template(
        template_name="profile_detail.html",
        context={
            "profile": profile,
            "chart_html": chart_html
        }
    )

def create_profiles_chart(profiles: list) -> str:
    """
    Create a stacked bar chart showing relative time for each range across profiles
    """
    if not profiles:
        return "<p style='text-align: center; color: #8b949e;'>No profiling data available</p>"

    # Get top ranges by average relative time across all profiles
    range_totals = {}
    for profile in profiles:
        for metric in profile.get('metrics', []):
            range_name = metric['range']
            rel_time = metric['relativeTime']
            if range_name == "simulate_pixels" or range_name == "run_simulation":
                continue
            if range_name not in range_totals:
                range_totals[range_name] = []
            range_totals[range_name].append(rel_time)

    # Calculate average and sort
    range_averages = {k: sum(v) / len(v) for k, v in range_totals.items()}
    top_ranges = sorted(range_averages.items(), key=lambda x: x[1], reverse=True)[:10]
    top_range_names = [r[0] for r in top_ranges]

    fig = go.Figure()

    # Create a bar for each range
    for range_name in top_range_names:
        x_labels = []
        y_values = []
        rel_times = []

        for profile in profiles:
            # Create label from timestamp and source file
            timestamp = profile.get('timestamp', '')
            if timestamp:
                label = timestamp.strftime('%Y-%m-%d %H:%M %Z') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
            else:
                label = str(profile.get('_id', ''))[:8]

            source = profile.get('source_file', '')
            if source:
                label = f"{label}<br>{source[:20]}"

            x_labels.append(label)

            for metric in profile.get('metrics', []):
                if metric['range'] == range_name:
                    tot_time = metric['totalTime'] / 1000.0
                    rel_time = metric['relativeTime']
                    break
            y_values.append(tot_time)
            rel_times.append(rel_time)

        fig.add_trace(go.Bar(
            name=range_name,
            x=x_labels,
            y=y_values,
            customdata=rel_times,
            text=[f"{range_name}<br>{v:.2f}s" for v in y_values],
            textposition='inside',
            textfont=dict(size=11),
            hovertemplate='<b>%{fullData.name}</b><br>' +
                          'Total: %{y:.2f}s<br>' +
                          'Relative: %{customdata:.1f}%<extra></extra>'
        ))

    fig.update_layout(
        barmode='stack',
        title='Profiling Data: Total Time by Range',
        xaxis_title='Profile Run',
        yaxis_title='Total Time (s)',
        template='plotly_dark',
        height=600,
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="top",
            y=1,
            xanchor="left",
            x=1.02
        ),
        margin=dict(r=200),
        plot_bgcolor='#0d1117',
        paper_bgcolor='#0d1117',
        font=dict(color='#c9d1d9')
    )

    return pio.to_html(fig, include_plotlyjs='cdn', div_id='profiles-chart')


def create_single_profile_chart(profile: dict) -> str:
    """
    Create a horizontal bar chart for a single profile showing relative times
    """
    metrics = profile.get('metrics', [])
    if not metrics:
        return "<p style='text-align: center; color: #8b949e;'>No metrics available</p>"

    # Sort by relative time descending
    sorted_metrics = sorted(metrics, key=lambda x: x['relativeTime'], reverse=True)

    # Take top 20 for readability
    top_metrics = sorted_metrics[:20]

    ranges = [m['range'] for m in top_metrics]
    rel_times = [m['relativeTime'] for m in top_metrics]
    total_times = [m['totalTime'] for m in top_metrics]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        y=ranges,
        x=rel_times,
        orientation='h',
        text=[f"{rt:.1f}%" for rt in rel_times],
        textposition='outside',
        marker=dict(
            color=rel_times,
            colorscale='Blues',
            showscale=True,
            colorbar=dict(title="Relative<br>Time (%)")
        ),
        hovertemplate='<b>%{y}</b><br>Relative: %{x:.2f}%<br>Total: %{customdata:.2f}ms<extra></extra>',
        cliponaxis=False,
        customdata=total_times
    ))

    source_file = profile.get('source_file', 'Unknown')
    timestamp = profile.get('timestamp', '')
    if hasattr(timestamp, 'strftime'):
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')
    else:
        timestamp_str = str(timestamp)

    fig.update_layout(
        title=f'Profile: {source_file}<br><sub>{timestamp_str}</sub>',
        xaxis_title='Relative Time (%)',
        yaxis_title='NVTX Range',
        template='plotly_dark',
        height=max(600, len(top_metrics) * 25),
        plot_bgcolor='#0d1117',
        paper_bgcolor='#0d1117',
        font=dict(color='#c9d1d9'),
        yaxis=dict(autorange='reversed')
    )

    return pio.to_html(fig, include_plotlyjs='cdn', div_id='profile-chart')

async def on_startup(app: Litestar) -> None:
    """Initialize MongoDB connection on startup"""
    logging.info("Starting GitHub Webhook Receiver...")
    logging.info(f"MongoDB: {MONGODB_URL}/{MONGODB_DB}")
    logging.info(f"Mongo user: {MONGODB_USER}")
    logging.info(
        f"Webhook Secret: {'Configured' if WEBHOOK_SECRET else 'Not configured (signatures will not be verified)'}"
    )
    client = AsyncMongoClient(
        MONGODB_URL, username=MONGODB_USER, password=MONGODB_PASS, serverSelectionTimeoutMS=15000
    )
    try:
        await client.admin.command("ping")
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

    status_code = 500
    error_title = "Internal Server Error"
    error_message = "An unexpected error occurred."

    if isinstance(exc, NotFoundException):
        status_code = 404
        error_title = "Page Not Found"
        error_message = "The page you're looking for doesn't exist."
    elif isinstance(exc, NotAuthorizedException):
        status_code = 401
        error_title = "Unauthorized"
        error_message = exc.detail or "Login required."
    elif isinstance(exc, HTTPException):
        status_code = exc.status_code
        error_title = f"Error {status_code}"
        error_message = exc.detail or "An error occurred."

    # Return HTML or JSON based on request header
    if preferred_type == MediaType.HTML:
        return Template(
            template_name="http_error.html",
            context={
                "status_code": status_code,
                "error_title": error_title,
                "error_message": error_message,
                "request_path": request.url.path,
            },
            status_code=status_code,
        )
    else:
        return Response(
            content={"error": error_title, "message": error_message, "status_code": status_code},
            status_code=status_code,
        )


# Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
MONGODB_DB = os.getenv("MONGODB_DB", "github_webhooks")
MONGODB_USER = os.getenv("MONGODB_USER", "")
MONGODB_PASS = os.getenv("MONGODB_PASS", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
VERIFY_IP = os.getenv("VERIFY_IP", "")
HPC_CLUSTER = os.getenv("HPC_CLUSTER", "perlmutter")
TZINFO = os.getenv("TZINFO", "US/Pacific")
TOKEN_URL = os.environ.get("TOKEN_URL", "https://oidc.nersc.gov/c2id/token")
ADMISSION_CONF_FILE = os.environ.get("ADMISSION_CONF_FILE", "configs/admission.yaml")
ADMISSION_CONF = read_admission_conf(ADMISSION_CONF_FILE)
JINJA_ENV = Environment(loader=PackageLoader("app"), enable_async=False)
LITESTAR_LOG_CONF = LoggingConfig(
    root={"level": "INFO", "handlers": ["queue_listener"]},
    formatters={"standard": {"format": "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"}},
    log_exceptions="always",
)

# Session cookie mirrors the guard's MAX_SESSION_AGE as a belt-and-suspenders
# measure: the browser stops sending the cookie at the same point the server
# would reject it anyway.
SESSION_CONFIG = CookieBackendConfig(
    secret=get_session_secret(),
    max_age=MAX_SESSION_AGE,
)

app = Litestar(
    route_handlers=[
        receive_webhook,  # POST /webhooks — GitHub webhook, intentionally unauthenticated
        list_webhooks,
        index,
        webhook_detail,
        display_queue,
        get_queue_info,
        profiles_list,
        profile_detail,
        create_static_files_router(path="/static", directories=["static"]),
        auth_router,  # /auth/login, /auth/callback, /auth/logout
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
