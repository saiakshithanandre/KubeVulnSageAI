"""
K8sVulnSage

A Retrieval-Augmented Generation (RAG) system for querying
Common Vulnerabilities and Exposures (CVEs) using PostgreSQL,
pgvector, Ollama, and Llama 3.2.
"""

from .config import (
    DB_CONFIG,
    EMBED_MODEL,
    CHAT_MODEL,
    TOP_K,
    SIMILARITY_THRESHOLD,
)

from .db import Database
from .llm import LLM
from .retriever import Retriever

__all__ = [
    "Database",
    "LLM",
    "Retriever",
    "DB_CONFIG",
    "EMBED_MODEL",
    "CHAT_MODEL",
    "TOP_K",
    "SIMILARITY_THRESHOLD",
]

__version__ = "1.0.0"
__author__ = "Akshitha"