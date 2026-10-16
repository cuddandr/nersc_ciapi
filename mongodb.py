"""
MongoDB integration.

Owns the MongoDBService data-access layer (webhooks + nsys profiles + the
admission policy) and the connection lifecycle hooks (on_startup/on_shutdown)
that app.py wires into the Litestar app.

The admission policy is the one piece of configuration stored in MongoDB:
it is mutable at runtime (edited via the web app) and seeded from the file
pointed to by ADMISSION_CONF_FILE on first run. All other configuration
comes from the environment (see config.py).
"""

import logging
from datetime import datetime
from typing import Any, Optional
from zoneinfo import ZoneInfo

import yaml
from bson import ObjectId
from bson.codec_options import CodecOptions
from litestar import Litestar
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from config import config, ConfigError


class MongoDBService:
    """MongoDB service for webhook storage"""

    def __init__(self, db: AsyncDatabase):
        options = CodecOptions(tz_aware=True, tzinfo=ZoneInfo(config.app.tzinfo))
        self.db = db
        self.collection = db.get_collection("webhooks", options)
        self.profiles_collection = db.get_collection("nsys_profiles", options)
        self.admission_collection = db.get_collection("admission_config", options)

    async def load_admission_conf(self) -> dict:
        """Load the admission policy from MongoDB (returns {} if absent)."""
        doc = await self.admission_collection.find_one({"_id": "policy"})
        if not doc:
            return {}
        return doc.get("data", {})

    async def save_admission_conf(self, admission_conf: dict) -> None:
        """Persist the admission policy to MongoDB (upsert)."""
        await self.admission_collection.update_one(
            {"_id": "policy"},
            {"$set": {"data": admission_conf}},
            upsert=True,
        )

    async def store_webhook(
        self, event_type: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> str:
        """Store a webhook event in MongoDB"""
        document = {
            "event_type": event_type,
            "payload": payload,
            "headers": headers,
            "received_at": datetime.now(ZoneInfo(self.config.app.tzinfo)),
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


def _validate_admission_conf(admission_conf: dict) -> None:
    """Validate the admission policy structure against the configured cluster."""
    if not admission_conf:
        logging.warning(
            "Admission config is empty; all webhooks will be rejected "
            "(or, if verify_ip is set, IP checks will fail)."
        )
        return
    if "clusters" not in admission_conf:
        raise ConfigError("Admission config is missing the required 'clusters' key.")
    if config.hpc.cluster not in admission_conf["clusters"]:
        raise ConfigError(
            f"Admission config has no entry under 'clusters' for "
            f"HPC_CLUSTER={config.hpc.cluster!r}."
        )


async def on_startup(app: Litestar) -> None:
    """Initialize MongoDB connection and load the admission policy."""
    logging.info("Starting GitHub Webhook Receiver...")
    logging.info(f"MongoDB: {config.mongodb.url}/{config.mongodb.db}")
    logging.info(f"Mongo user: {config.mongodb.user}")
    logging.info(
        f"Webhook Secret: {'Configured' if config.webhook.secret else 'Not configured (signatures will not be verified)'}"
    )

    client = AsyncMongoClient(
        config.mongodb.url,
        username=config.mongodb.user,
        password=config.mongodb.password,
        serverSelectionTimeoutMS=15000,
    )
    try:
        await client.admin.command("ping")
        db = client[config.mongodb.db]
        app.state.mongo_service = MongoDBService(db)

        # Load the admission policy from MongoDB; seed from the file on
        # first run. The DB copy is authoritative once it exists.
        mongo_service: MongoDBService = app.state.mongo_service
        admission_conf = await mongo_service.load_admission_conf()
        if admission_conf:
            logging.info("Loaded admission config from MongoDB.")
        elif config.hpc.admission_conf_file:
            logging.info(
                "No admission config in MongoDB. Seeding from "
                f"{config.hpc.admission_conf_file}."
            )
            with open(config.hpc.admission_conf_file, "r") as f:
                admission_conf = yaml.safe_load(f) or {}
            if admission_conf:
                await mongo_service.save_admission_conf(admission_conf)
                logging.info("Seeded admission config into MongoDB.")
        else:
            logging.warning(
                "No admission config in MongoDB and ADMISSION_CONF_FILE is "
                "not set; admission checks are disabled."
            )

        _validate_admission_conf(admission_conf)
        app.state.admission_conf = admission_conf

        logging.info(f"Connected to MongoDB: {config.mongodb.url}/{config.mongodb.db}")
    except Exception as e:
        app.state.mongo_service = None
        app.state.mongo_error = e
        logging.error(f"Error during startup: {e}")


async def on_shutdown(app: Litestar) -> None:
    """Close MongoDB connection on shutdown"""
    logging.info("Application shutting down")
