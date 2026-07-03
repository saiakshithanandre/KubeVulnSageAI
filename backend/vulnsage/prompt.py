def build_prompt(question, docs):

    context = ""

    for cve_id, title, description, similarity in docs:

        context += f"""
CVE: {cve_id}
Title: {title}

Description:
{description}

Similarity: {similarity:.3f}

---------------------------------------
"""

    return f"""
You are a cybersecurity assistant.

Use ONLY the supplied CVEs.

If the answer cannot be determined,
say so.

Context:

{context}

Question:

{question}

Provide:

• concise answer

• relevant CVE IDs

• explanation
"""