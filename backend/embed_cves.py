# import psycopg2
# import ollama
#
# # PostgreSQL connection
# DB_CONFIG = {
#     "host": "localhost",
#     "port": 5433,
#     "dbname": "cvedb",
#     "user": "cve",
#     "password": "cve",
# }
#
# EMBED_MODEL = "nomic-embed-text"
#
#
# def get_embedding(text: str):
#     """Generate embedding using Ollama."""
#     response = ollama.embed(
#         model=EMBED_MODEL,
#         input=text,
#     )
#     return response["embeddings"][0]
#
#
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     cur = conn.cursor()
#
#     # Read only rows without embeddings
#     cur.execute("""
#         SELECT cve_id, title, description
#         FROM cves
#         WHERE embedding IS NULL
#         ORDER BY cve_id;
#     """)
#
#     rows = cur.fetchall()
#
#     print(f"Found {len(rows)} CVEs to embed.\n")
#
#     for idx, (cve_id, title, description) in enumerate(rows, start=1):
#
#         text = f"{title or ''}\n\n{description or ''}"
#
#         try:
#             embedding = get_embedding(text)
#
#             cur.execute(
#                 """
#                 UPDATE cves
#                 SET embedding = %s
#                 WHERE cve_id = %s;
#                 """,
#                 (embedding, cve_id),
#             )
#
#             conn.commit()
#
#             print(f"[{idx}/{len(rows)}] Embedded {cve_id}")
#
#         except Exception as e:
#             conn.rollback()
#             print(f"Failed: {cve_id}")
#             print(e)
#
#     cur.close()
#     conn.close()
#
#     print("\nFinished embedding all CVEs.")
#
#
# if __name__ == "__main__":
#     main()

import os
import time

import ollama
import psycopg2
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

DB = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

MODEL = os.getenv("EMBED_MODEL")

BATCH_SIZE = 100
MAX_RETRIES = 3


def get_embedding(text: str):
    """
    Generate embedding with retry logic.
    """

    for attempt in range(MAX_RETRIES):

        try:
            response = ollama.embed(
                model=MODEL,
                input=text,
            )

            return response["embeddings"][0]

        except Exception as e:

            print(
                f"Retry {attempt+1}/{MAX_RETRIES} failed..."
            )

            if attempt == MAX_RETRIES - 1:
                raise e

            time.sleep(2)


def main():

    conn = psycopg2.connect(**DB)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            cve_id,
            title,
            description
        FROM cves
        WHERE embedding IS NULL
        ORDER BY cve_id;
        """
    )

    rows = cur.fetchall()

    print(f"\nEmbedding {len(rows)} CVEs...\n")

    batch = []

    for i, (cve_id, title, description) in enumerate(
        tqdm(rows),
        start=1,
    ):

        text = f"{title or ''}\n\n{description or ''}"

        embedding = get_embedding(text)

        batch.append(
            (
                embedding,
                cve_id,
            )
        )

        if len(batch) == BATCH_SIZE or i == len(rows):

            cur.executemany(
                """
                UPDATE cves
                SET embedding=%s
                WHERE cve_id=%s;
                """,
                batch,
            )

            conn.commit()

            batch.clear()

    cur.close()
    conn.close()

    print("\nAll embeddings generated successfully.")


if __name__ == "__main__":
    main()