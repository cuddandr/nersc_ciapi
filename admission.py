"""
Admission configuration management.

Serves the /admission page (YAML editor) plus the JSON endpoints that read,
save, and reload the admission policy stored in MongoDB. Saving validates
the new policy before persisting it and updates the in-memory copy on
app.state so changes take effect without a restart.
"""

import logging
from typing import Any

import yaml
from litestar import Request, Router, get, post
from litestar.datastructures import State
from litestar.exceptions import HTTPException
from litestar.response import Template

from auth import require_login, require_ldap_group, session_user_context
from config import config, ConfigError
from mongodb import MongoDBService, _validate_admission_conf


@get("/admission", guards=[require_login, require_ldap_group(config.ldap.admin_group)])
async def admission_page(request: Request, state: State) -> Template:
    """
    Page displaying and editing the admission policy.

    Shows the current policy as editable YAML plus Save and Reload buttons.
    """
    # Check if connection established to MongoDB and show error page if not
    if not hasattr(state, "mongo_service") or state.mongo_service is None:
        return Template(
            template_name="mongo_error.html",
            context={
                "error_type": "MongoDB Connection Failed",
                "mongodb_url": config.mongodb.url,
                "mongodb_db": config.mongodb.db,
                "error_message": str(getattr(state, "mongo_error", "")),
                "request": request,
                **session_user_context(request),
            },
        )

    return Template(
        template_name="admission.html",
        context={
            "request": request,
            **session_user_context(request),
        },
    )


@get("/admission-data", guards=[require_login, require_ldap_group(config.ldap.admin_group)])
async def get_admission_data(state: State) -> dict[str, Any]:
    """Return the current admission policy as YAML text for the editor."""
    mongo_service: MongoDBService = state.mongo_service
    admission_conf = state.admission_conf
    return {"yaml": yaml.safe_dump(admission_conf, sort_keys=False)}


@post("/admission/save", guards=[require_login, require_ldap_group(config.ldap.admin_group)])
async def save_admission_data(request: Request, state: State) -> dict[str, Any]:
    """
    Validate the submitted YAML, persist it to MongoDB, and update the
    in-memory policy on app.state so it takes effect immediately.
    """
    body = await request.json()
    yaml_text = body.get("yaml", "") if isinstance(body, dict) else ""

    try:
        admission_conf = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    if not isinstance(admission_conf, dict):
        raise HTTPException(status_code=400, detail="Admission config must be a YAML mapping.")

    try:
        _validate_admission_conf(admission_conf)
    except ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))

    mongo_service: MongoDBService = state.mongo_service
    await mongo_service.save_admission_conf(admission_conf)
    state.admission_conf = admission_conf
    logging.info("Admission config updated via web UI.")

    return {"status": "ok", "message": "Admission config saved and applied."}


@post("/admission/reload", guards=[require_login, require_ldap_group(config.ldap.admin_group)])
async def reload_admission_data(state: State) -> dict[str, Any]:
    """
    Re-read the admission policy from MongoDB into app.state, discarding any
    unsaved editor changes. Use after editing the DB directly or from another
    app instance.
    """
    mongo_service: MongoDBService = state.mongo_service
    admission_conf = await mongo_service.load_admission_conf()
    _validate_admission_conf(admission_conf)
    state.admission_conf = admission_conf
    logging.info("Admission config reloaded from MongoDB.")

    return {"status": "ok", "message": "Admission config reloaded from MongoDB."}


admission_router = Router(
    path="/",
    route_handlers=[admission_page, get_admission_data, save_admission_data, reload_admission_data],
)
