import psycopg2
from .config import DB_CONFIG, TOP_K, SIMILARITY_THRESHOLD

class Database:

    def __init__(self):
        self.conn = psycopg2.connect(**DB_CONFIG)
        self.cur = self.conn.cursor()

    def close(self):
        self.cur.close()
        self.conn.close()

    def lookup_cve(self, cve_id):

        self.cur.execute("""
            SELECT
                cve_id,
                title,
                description
            FROM cves
            WHERE cve_id=%s;
        """, (cve_id,))

        return self.cur.fetchone()

    def semantic_search(self, embedding):

        self.cur.execute("""
            SELECT
                cve_id,
                title,
                description,
                1 - (embedding <=> %s::vector) AS similarity
            FROM cves
            WHERE embedding IS NOT NULL
              AND (1 - (embedding <=> %s::vector)) >= %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
        """, (
            embedding,
            embedding,
            SIMILARITY_THRESHOLD,
            embedding,
            TOP_K
        ))

        return self.cur.fetchall()