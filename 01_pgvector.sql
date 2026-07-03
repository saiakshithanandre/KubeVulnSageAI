-- Phase 1: add vector search to the existing cves table.
-- Runs after schema.sql. nomic-embed-text produces 768-dim vectors.

CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE cves ADD COLUMN IF NOT EXISTS embedding vector(768);

-- HNSW index for fast cosine-similarity search
-- (only indexes rows once they have an embedding).
CREATE INDEX IF NOT EXISTS idx_cves_embedding
    ON cves USING hnsw (embedding vector_cosine_ops);
