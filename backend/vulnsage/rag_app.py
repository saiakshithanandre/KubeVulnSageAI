import os

import ollama
import psycopg2
from dotenv import load_dotenv

load_dotenv()

DB = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

EMBED_MODEL = os.getenv("EMBED_MODEL")
CHAT_MODEL = os.getenv("CHAT_MODEL")
TOP_K = int(os.getenv("TOP_K", 5))


class CVERAG:

    def __init__(self):

        self.conn = psycopg2.connect(**DB)
        self.cur = self.conn.cursor()

    def embed(self, text):

        response = ollama.embed(
            model=EMBED_MODEL,
            input=text,
        )

        return response["embeddings"][0]

    def search(self, question):

        embedding = self.embed(question)

        self.cur.execute(
            """
            SELECT
                cve_id,
                title,
                description,
                1 - (embedding <=> %s::vector) AS similarity
            FROM cves
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
            """,
            (
                embedding,
                embedding,
                TOP_K,
            ),
        )

        return self.cur.fetchall()

    def build_prompt(self, question, docs):

        context = ""

        for cve_id, title, description, similarity in docs:

            context += f"""
CVE: {cve_id}

Title:
{title}

Description:
{description}

Similarity:
{similarity:.3f}

-----------------------------
"""

        prompt = f"""
You are a Kubernetes Security Assistant.

Answer ONLY using the CVEs provided below.

If the answer cannot be determined from these CVEs,
say that the information is unavailable.

=========================

{context}

=========================

Question:

{question}

Provide:

1. A concise answer.

2. Mention the relevant CVE IDs.

3. Explain why they are relevant.

"""

        return prompt

    def ask(self, question):

        docs = self.search(question)

        prompt = self.build_prompt(
            question,
            docs,
        )

        response = ollama.chat(
            model=CHAT_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        return docs, response["message"]["content"]

    def close(self):

        self.cur.close()
        self.conn.close()


def main():

    rag = CVERAG()

    print("=" * 60)
    print(" K8sVulnSage ")
    print("=" * 60)

    while True:

        question = input("\nAsk a question ('exit' to quit): ")

        if question.lower() in ("exit", "quit"):

            break

        docs, answer = rag.ask(question)

        print("\nRetrieved CVEs")
        print("-" * 60)

        for cve_id, title, _, similarity in docs:

            print(f"{cve_id} | {similarity:.3f}")
            print(title)
            print()

        print("=" * 60)
        print("Answer")
        print("=" * 60)
        print(answer)

    rag.close()


if __name__ == "__main__":
    main()