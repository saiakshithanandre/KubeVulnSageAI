from .db import Database
from .llm import LLM
from .utils import extract_cve_id
from .prompt import build_prompt

class Retriever:

    def __init__(self):

        self.db = Database()
        self.llm = LLM()

    def ask(self, question):

        cve = extract_cve_id(question)

        if cve:

            result = self.db.lookup_cve(cve)

            if not result:
                return f"{cve} not found."

            cve_id, title, description = result

            return f"""
CVE ID

{cve_id}

Title

{title}

Description

{description}
"""

        embedding = self.llm.embed(question)

        docs = self.db.semantic_search(embedding)

        if not docs:

            return "No relevant CVEs found."

        prompt = build_prompt(question, docs)

        return self.llm.chat(prompt)

    def close(self):

        self.db.close()