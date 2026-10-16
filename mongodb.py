"""
MongoDB integration.

Owns the MongoDBService data-access layer (webhooks + nsys profiles) and
the connection lifecycle hooks (on_startup/on_shutdown) that app.py wires
into the Litestar app.
"""

import logging
from datetime import datetime
from typing import Any, Optional
from zoneinfo import ZoneInfo

from bson import ObjectId
from bson.codec_options import CodecOptions
from litestar import Litestar
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from config import bootstrap, Config


class MongoDBService:
    """MongoDB service for webhook storage"""

    def __init__(self, db: AsyncDatabase, config: Config):
        options = CodecOptions(tz_aware=True, tzinfo=ZoneInfo(config.app.tzinfo))
        self.db = db
        self.config = config
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


async def on_startup(app: Litestar) -> None:
    """Initialize MongoDB connection and load configuration on startup"""
    logging.info("Starting GitHub Webhook Receiver...")
    logging.info(f"MongoDB: {bootstrap.mongodb_url}/{bootstrap.mongodb_db}")
    logging.info(f"Mongo user: {bootstrap.mongodb_user}")

    client = AsyncMongoClient(
        bootstrap.mongodb_url,
        username=bootstrap.mongodb_user,
        password=bootstrap.mongodb_password,
        serverSelectionTimeoutMS=15000,
    )
    try:
        await client.admin.command("ping")
        db = client[bootstrap.mongodb_db]

        # Load configuration from MongoDB, seed if not present
        conf_collection = db.get_collection("configurations")
        conf_doc = await conf_collection.find_one({"_id": "app_config"})

        if conf_doc:
            logging.info("Loading configuration from MongoDB.")
            # Remove MongoDB internal _id
            config_data = {k: v for k, v in conf_doc.items() if k != "_id"}
            app_config = Config.from_dict(config_data)
        else:
            logging.info("No configuration found in MongoDB. Seeding from environment/files.")
            app_config = Config.from_env()
            await conf_collection.insert_one({
                "_id": "app_config",
                **app_config.to_dict()
            })

        app_config.validate()
        app.state.config = app_config
        app.state.mongo_service = MongoDBService(db, app_config)

        logging.info(f"Connected to MongoDB: {bootstrap.mongodb_url}/{bootstrap.mongodb_db}")
        logging.info(
            f"Webhook Secret: {'Configured' if app_config.webhook.secret else 'Not configured'}"
        )
    except Exception as e:
        app.state.mongo_service = None
        app.state.mongo_error = e
        logging.error(f"Error during startup: {e}")


async def on_shutdown(app: Litestar) -> None:
    """Close MongoDB connection on shutdown"""
    logging.info("Application shutting down")
