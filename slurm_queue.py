"""
Perlmutter SLURM queue status.

Polls `sacct` on the HPC cluster via the NERSC Superfacility API and
exposes it as JSON (/queue-data) plus a dashboard page (/queue).
"""

import json
import logging
import time
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import jq
import litestar.status_codes as status_code
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from litestar import Request, Router, Response, get
from litestar.datastructures import State
from litestar.response import Template

from auth import require_login, session_user_context
from config import Config
from utils import read_file_content


def filter_sacct(data: dict, config: Config) -> dict:
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
        job["start"] = datetime.fromtimestamp(job["start"], tz=ZoneInfo(config.app.tzinfo)).strftime(
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
async def get_queue_info(request: Request, state: State, days: int = 1) -> Response:
    wait_time = 15  # seconds to wait in between polling the SF API task
    num_attempts = 4  # total tries to get the data before giving up

    config: Config = state.config
    cluster = config.hpc.admission_conf["clusters"][config.hpc.cluster]
    client_id = read_file_content(cluster["client_id"]).strip()
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
    # Build command to get SLURM queue via sacct
    start_date = date.today() - timedelta(days=days)
    cmd = f'bash -c "sacct -a -X -A dune,dune_g --json -S {start_date}"'
    try:
        # Run sacct on Perlmutter
        logging.info(f"Running sacct on {config.hpc.cluster}")
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
            if get_output["result"] and get_output["status"] != "failed":
                task_output = json.loads(get_output["result"])
                task_output = json.loads(task_output["output"])
                data["jobs"] = task_output["jobs"]
                http_status_code = status_code.HTTP_200_OK
                break
            else:
                time.sleep(wait_time)

        filtered = filter_sacct(data, config)
        return Response(
            content=filtered,
            status_code=http_status_code,
        )

    except Exception as e:
        logging.error(f"An error occurred accessing SF API: {e}")
        return Response(content={"error": str(e)}, status_code=status_code.HTTP_400_BAD_REQUEST)


@get("/queue", guards=[require_login])
async def display_queue(request: Request, state: State, days: int = 1) -> Template:
    """
    Display Perlmutter job queue. Serves an initially empty webpage
    with loading animation. A JS script inside the HTML performs an
    API call to get the queue info and dynamically update the page.
    """
    return Template(
        template_name="slurm_queue.html",
        context={
            "request": request,
            **session_user_context(request),
        }
    )


queue_router = Router(path="/", route_handlers=[display_queue, get_queue_info])
