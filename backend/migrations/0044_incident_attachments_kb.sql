-- §6.8 case management slice C: attachments / chain-of-custody (CASE-008) and knowledge-base links
-- (CASE-010). Reaches §6.8 FULL.

-- ── CASE-008: attachments with chain-of-custody ─────────────────────────────────────────────────────
-- Evidence files are IMMUTABLE: bytes live in the blob store; the row records the sha256 digest so any
-- later retrieval can be verified against what was ingested (chain-of-custody). The app role is granted
-- only SELECT + INSERT — never UPDATE/DELETE — so custody metadata cannot be altered or erased through
-- the application (defence in depth beyond audit).
CREATE TABLE IF NOT EXISTS incident_attachments (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  incident_id  uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  filename     text NOT NULL,
  content_type text NOT NULL DEFAULT 'application/octet-stream',
  size_bytes   bigint NOT NULL DEFAULT 0,
  sha256       text NOT NULL,               -- hex digest of the stored bytes (chain-of-custody)
  blob_uri     text NOT NULL,               -- blob store URI
  note         text NOT NULL DEFAULT '',
  uploaded_by  uuid,
  uploaded_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_attachments_lookup ON incident_attachments (tenant_id, incident_id);

ALTER TABLE incident_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_attachments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_attachments;
CREATE POLICY tenant_isolation ON incident_attachments
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
-- Immutable: no UPDATE / DELETE grant to the app role (chain-of-custody).
GRANT SELECT, INSERT ON incident_attachments TO nirvet_app;

-- ── CASE-010: knowledge base + incident links ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_articles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid,                          -- NULL = global (shared playbook/runbook library)
  title       text NOT NULL,
  body        text NOT NULL DEFAULT '',
  url         text NOT NULL DEFAULT '',      -- optional external link (wiki/runbook)
  category    text NOT NULL DEFAULT '',
  tags        text[] NOT NULL DEFAULT '{}',
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS knowledge_articles_tenant ON knowledge_articles (tenant_id);

ALTER TABLE knowledge_articles ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_articles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS knowledge_articles_select ON knowledge_articles;
DROP POLICY IF EXISTS knowledge_articles_insert ON knowledge_articles;
DROP POLICY IF EXISTS knowledge_articles_update ON knowledge_articles;
DROP POLICY IF EXISTS knowledge_articles_delete ON knowledge_articles;
CREATE POLICY knowledge_articles_select ON knowledge_articles
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY knowledge_articles_insert ON knowledge_articles
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY knowledge_articles_update ON knowledge_articles
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY knowledge_articles_delete ON knowledge_articles
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge_articles TO nirvet_app;

CREATE TABLE IF NOT EXISTS incident_kb_links (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  article_id  uuid NOT NULL REFERENCES knowledge_articles(id) ON DELETE CASCADE,
  linked_by   uuid,
  linked_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, incident_id, article_id)
);
CREATE INDEX IF NOT EXISTS incident_kb_links_lookup ON incident_kb_links (tenant_id, incident_id);

ALTER TABLE incident_kb_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_kb_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_kb_links;
CREATE POLICY tenant_isolation ON incident_kb_links
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_kb_links TO nirvet_app;

-- Seed a couple of GLOBAL runbook stubs so the KB is non-empty and every tenant can link them.
INSERT INTO knowledge_articles (tenant_id, title, category, body, url) VALUES
  (NULL,'Phishing Response Runbook','phishing','Triage, contain, and remediate a reported phishing email.','https://runbooks.nirvet/phishing'),
  (NULL,'Ransomware Containment Runbook','malware','Isolate, assess blast radius, and coordinate recovery.','https://runbooks.nirvet/ransomware'),
  (NULL,'Account Compromise Runbook','unauthorized_access','Reset credentials, revoke sessions, and review sign-in logs.','https://runbooks.nirvet/account-compromise')
ON CONFLICT DO NOTHING;
