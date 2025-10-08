#!/usr/bin/env python3

import argparse
import json
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import sys


def connect_to_mongodb(connection_string, timeout=5000, verbose=False):
    """
    Establish connection to MongoDB.

    Args:
        connection_string: MongoDB connection URI
        timeout: Connection timeout in milliseconds

    Returns:
        MongoClient instance or None if connection fails
    """
    try:
        client = MongoClient(connection_string, serverSelectionTimeoutMS=timeout)
        client.admin.command('ping')
        if verbose:
            print("Successfully connected to MongoDB")
        return client
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        print(f"Failed to connect to MongoDB: {e}", file=sys.stderr)
        return None


def find_document(collection, query):
    """
    Find a single document in the collection.

    Args:
        collection: PyMongo collection object
        query: Dictionary representing the query

    Returns:
        Document if found, None otherwise
    """
    try:
        document = collection.find_one(query)
        return document
    except Exception as e:
        print(f"Error finding document: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Access MongoDB documents via command line'
    )

    parser.add_argument(
        '--uri',
        type=str,
        default='mongodb://localhost:27017/',
        help='MongoDB connection URI (default: mongodb://localhost:27017/)'
    )

    parser.add_argument(
        '-d',
        '--database',
        type=str,
        required=True,
        help='Database name'
    )

    parser.add_argument(
        '-c',
        '--collection',
        type=str,
        required=True,
        help='Collection name'
    )

    parser.add_argument(
        '--field',
        type=str,
        required=True,
        help='Field name to query'
    )

    parser.add_argument(
        '--value',
        type=str,
        required=True,
        help='Field value to search for'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Enable verbosity'
    )

    args = parser.parse_args()

    client = connect_to_mongodb(args.uri, verbose=args.verbose)
    if not client:
        sys.exit(1)

    try:
        db = client[args.database]
        collection = db[args.collection]

        if args.field == "_id":
            value = ObjectId(args.value)
        else:
            value = args.value
        query = {args.field: value}

        if args.verbose:
            print(f"\nSearching for document where {args.field} = {args.value}")
        document = find_document(collection, query)

        if document:
            print(json.dumps(document['payload']))
        else:
            if args.verbose:
                print("\nNo document found matching the query.")
            print("{}")

    finally:
        client.close()
        if args.verbose:
            print("\nConnection closed.")


if __name__ == "__main__":
    main()
