#!/usr/bin/env python3
"""
Upload performance benchmark CSV files to MongoDB.

Environment Variables:
    MONGODB_URI: MongoDB connection URI (default: mongodb://localhost:27017/)
    MONGODB_USER: MongoDB username (optional)
    MONGODB_PASSWORD: MongoDB password (optional)
    MONGODB_DATABASE: Database name (default: benchmarking_db)
"""

import argparse
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure


def parse_csv_file(filepath: Path) -> List[Dict[str, Any]]:
    """Parse CSV file and return list of metric dictionaries."""
    metrics = []

    with open(filepath, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)

        for row in reader:
            try:
                metrics.append({
                    'relativeTime': float(row['Rel. Time (%)']),
                    'totalTime': float(row['Total Time (ms)']),
                    'instances': int(row['Instances']),
                    'avg': float(row['Avg (ms)']),
                    'median': float(row['Med (ms)']),
                    'min': float(row['Min (ms)']),
                    'max': float(row['Max (ms)']),
                    'stdDev': float(row['StdDev (ms)']),
                    'range': row['Range']
                })
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping invalid row in {filepath}: {e}", file=sys.stderr)
                continue

    return metrics


def create_document(filepath: Path, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create MongoDB document from metrics data."""
    return {
        'timestamp': datetime.now(),
        'source_file': filepath.name,
        'metrics': metrics,
        'total_ranges': len(metrics),
        'total_time_ms': metrics[0]['totalTime'],
    }


def upload_csv_files(csv_files: List[Path], database_name: str, collection_name: str,
                     dry_run: bool = False) -> None:
    """Upload CSV files to MongoDB."""

    mongo_url = os.getenv('MONGODB_URL', 'mongodb://localhost:27017/')
    mongo_user = os.getenv('MONGODB_USER')
    mongo_pass = os.getenv('MONGODB_PASSWORD')

    # Connect to MongoDB
    try:
        # client = MongoClient(mongo_uri, username=mongo_user, password=mongo_pass, serverSelectionTimeoutMS=5000)
        client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print(f"Connected to MongoDB: {mongo_url}")
    except ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        db = client[database_name]
        collection = db[collection_name]

        print(f"Using database: {database_name}")
        print(f"Using collection: {collection_name}")
        print("-" * 50)

        successful_uploads = 0
        failed_uploads = 0

        for csv_file in csv_files:
            if not csv_file.exists():
                print(f"File not found: {csv_file}")
                failed_uploads += 1
                continue

            print(f"Processing: {csv_file.name}")

            try:
                # Parse CSV
                metrics = parse_csv_file(csv_file)

                if not metrics:
                    print(f"No valid metrics found in {csv_file.name}")
                    failed_uploads += 1
                    continue

                # Create document
                document = create_document(csv_file, metrics)

                if dry_run:
                    print(f"[DRY RUN] Would insert document with {len(metrics)} metrics")
                else:
                    # Insert document
                    result = collection.insert_one(document)
                    print(f"Inserted document with _id: {result.inserted_id}")

                successful_uploads += 1

            except Exception as e:
                print(f"Error processing {csv_file.name}: {e}")
                failed_uploads += 1

        # Summary
        print("-" * 50)
        print(f"Upload Summary:")
        print(f"Successful: {successful_uploads}")
        print(f"Failed: {failed_uploads}")
        print(f"Total : {len(csv_files)}")

    except OperationFailure as e:
        print(f"MongoDB operation failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description='Upload nsys performance benchmark CSV files to MongoDB',
    )

    parser.add_argument(
        'csv_files',
        nargs='+',
        type=Path,
        help='CSV file(s) to upload'
    )

    parser.add_argument(
        '-d', '--database',
        default=os.getenv('MONGODB_DATABASE', 'benchmarking_db'),
        help='MongoDB database name (default: benchmarking_db or MONGODB_DATABASE env var)'
    )

    parser.add_argument(
        '-c', '--collection',
        default='benchmarking',
        help='MongoDB collection name (default: benchmarking)'
    )

    parser.add_argument(
        '-n', '--dry-run',
        action='store_true',
        help='Parse files but do not insert into MongoDB'
    )

    args = parser.parse_args()

    # Upload files
    upload_csv_files(
        csv_files=args.csv_files,
        database_name=args.database,
        collection_name=args.collection,
        dry_run=args.dry_run
    )


if __name__ == '__main__':
    main()
