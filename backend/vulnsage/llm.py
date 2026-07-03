import time
import ollama

from .config import CHAT_MODEL, EMBED_MODEL

class LLM:

    def embed(self, text):

        for _ in range(3):

            try:

                return ollama.embed(
                    model=EMBED_MODEL,
                    input=text
                )["embeddings"][0]

            except Exception:

                time.sleep(2)

        raise RuntimeError("Embedding failed")

    def chat(self, prompt):

        for _ in range(3):

            try:

                return ollama.chat(
                    model=CHAT_MODEL,
                    messages=[
                        {
                            "role":"user",
                            "content":prompt
                        }
                    ]
                )["message"]["content"]

            except Exception:

                time.sleep(2)

        raise RuntimeError("Chat failed")