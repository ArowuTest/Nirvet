-- Investigation notebooks (SRS §6.9 slice B, UI-depth Bucket B / B2). A private, persisted analyst working
-- surface: a titled notebook of ordered cells (a markdown note, or a saved hunt-query text). Notebooks are PRIVATE
-- to the creating analyst (user_id) within their tenant; cells belong to a notebook. A 'query' cell only STORES
-- the query text — it is not executed here (execution stays the allow-list-compiled run-hunt-query path). Both
-- tables are tenant-scoped RLS FORCE; owner_bypass is added by 0126's loop (managed-PG requirement, see 0118/0122).

CREATE TABLE IF NOT EXISTS investigation_notebooks (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  user_id      uuid NOT NULL,              -- owning analyst; notebooks are private to their creator
  title        text NOT NULL DEFAULT 'Untitled investigation',
  incident_ref uuid,                        -- optional: the incident this notebook investigates
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_investigation_notebooks_owner
  ON investigation_notebooks (tenant_id, user_id, updated_at DESC);

ALTER TABLE investigation_notebooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_notebooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON investigation_notebooks;
CREATE POLICY tenant_isolation ON investigation_notebooks
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_notebooks TO nirvet_app;

CREATE TABLE IF NOT EXISTS investigation_notebook_cells (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  notebook_id uuid NOT NULL REFERENCES investigation_notebooks (id) ON DELETE CASCADE,
  position    int  NOT NULL DEFAULT 0,      -- append order; reorder swaps positions
  kind        text NOT NULL CHECK (kind IN ('note', 'query')),
  content     text NOT NULL DEFAULT '',     -- markdown for 'note'; the hunt-query text for 'query'
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_investigation_notebook_cells_nb
  ON investigation_notebook_cells (notebook_id, position);

ALTER TABLE investigation_notebook_cells ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_notebook_cells FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON investigation_notebook_cells;
CREATE POLICY tenant_isolation ON investigation_notebook_cells
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_notebook_cells TO nirvet_app;
