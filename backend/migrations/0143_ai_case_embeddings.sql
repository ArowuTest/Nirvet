-- 0143 — RAG over case history (§6.12 copilot completion incr3, #180). The copilot's institutional memory: past
-- incident chunks are embedded into a per-tenant vector store so a similar prior case can be recalled to ground an
-- answer. This is the MOST security-sensitive AI surface — the vector store IS customer data. Two non-negotiables:
--   1. PER-TENANT, RLS'd, NEVER retrieved across tenants (a RAG that returns tenant B's incident to tenant A is
--      catastrophic). The table is FORCE-RLS'd; retrieval runs WithTenant, so the similarity query is RLS-confined.
--   2. Retention-aware — deleted data leaves the index. The FK to incidents is ON DELETE CASCADE, so when an incident
--      is deleted (retention-delete / B3) its embeddings are purged automatically; the RAG can never resurrect it.
-- Field-visibility (2b): each chunk carries a min_role floor; retrieval returns only chunks the acting analyst may see
-- (same seam as the hunt field-registry / RunHunt maskRows). The embedding itself is generated locally by default (a
-- deterministic in-process embedder — nothing leaves the perimeter), so no new egress door opens here.

-- The `vector` extension (pgvector). Like 0100's pg_trgm: the migrate role runs as a superuser-equivalent (owner), so
-- CREATE EXTENSION succeeds; a sovereign/self-managed Postgres and pgvector/pgvector:pg17 (CI + compose) provide it.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS ai_case_embeddings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL DEFAULT app_current_tenant(),
  -- The incident this chunk came from. ON DELETE CASCADE = retention-aware: deleting the incident purges its
  -- embeddings (test #6), so the index never outlives the data.
  incident_ref  uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  -- The redactable chunk text (customer telemetry). On retrieval it rides completeExternal as the untrusted evidence
  -- bag, redacted per the acting analyst — it is never treated as an instruction.
  chunk         text NOT NULL,
  -- Field-visibility floor (2b): a role must MEET this to retrieve the chunk. Default light = analyst_t1 (everyone),
  -- so the seam elevates by row, mirroring the hunt field-registry MinRole.
  min_role      text NOT NULL DEFAULT 'analyst_t1',
  -- The embedding vector. 256-dim matches the in-process deterministic embedder (the sovereign default: no egress).
  -- A future cloud/self-hosted embedding provider that produces a different dim re-enters the gate (its own egress
  -- review); this column's dimension is fixed for the local embedder's first slice.
  embedding     vector(256) NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE ai_case_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_case_embeddings FORCE ROW LEVEL SECURITY;

-- THE CRUX: tenant isolation. Retrieval runs WithTenant(p.TenantID); this policy makes the similarity query
-- RLS-confined, so tenant A can only ever see its own embeddings. A two-tenant test proves no cross-tenant retrieval.
DROP POLICY IF EXISTS tenant_isolation ON ai_case_embeddings;
CREATE POLICY tenant_isolation ON ai_case_embeddings
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

-- owner_bypass (mig 0118 pattern / schemacheck guard #5): FORCE RLS also constrains the table OWNER, so a
-- SECURITY DEFINER function running as the non-superuser managed-DB owner would read ZERO rows without this. Restores
-- the owner's exemption without weakening nirvet_app (never the owner).
DROP POLICY IF EXISTS owner_bypass ON ai_case_embeddings;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON ai_case_embeddings USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;

-- The app indexes (INSERT), retrieves (SELECT), and PURGES (DELETE — retention age-out / re-index) its OWN tenant's
-- embeddings; TRUNCATE is never needed.
REVOKE TRUNCATE ON ai_case_embeddings FROM nirvet_app;
GRANT SELECT, INSERT, DELETE ON ai_case_embeddings TO nirvet_app;

-- Purge-by-incident + tenant-scoped listing.
CREATE INDEX IF NOT EXISTS ai_case_embeddings_incident ON ai_case_embeddings (tenant_id, incident_ref);
-- Cosine similarity index (pgvector HNSW). Retrieval orders by embedding <=> query (cosine distance); HNSW keeps top-K
-- fast as the store grows. RLS is applied first, so the index only ever serves the caller's own tenant.
CREATE INDEX IF NOT EXISTS ai_case_embeddings_vec ON ai_case_embeddings USING hnsw (embedding vector_cosine_ops);
