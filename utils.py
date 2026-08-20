"""Small helpers shared by more than one module."""

import logging


def read_file_content(file_path: str) -> str:
    """Read content from a file and return as a string.

    Used for per-cluster credential files referenced from the admission
    config (client_id / private_key paths), as opposed to the top-level
    secrets config.py resolves itself.
    """
    try:
        with open(file_path, "r") as file:
            return file.read()
    except Exception as e:
        logging.error(f"Error: {e}")
        return ""
