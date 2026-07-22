package recovery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresValidation is the evidence produced by validating a restored database.
// Every finding is fail-closed; callers must not convert partial evidence into a pass.
type PostgresValidation struct {
	IntegrityEvidence string
	SecurityEvidence  string
	TenantEvidence    string
}

// ValidateRestoredPostgres re-asserts load-bearing database invariants against
// the RESTORED instance. It does not mutate or repair the database.
func ValidateRestoredPostgres(ctx context.Context, pool *pgxpool.Pool) (PostgresValidation, error) {
	if pool == nil {
		return PostgresValidation{}, fmt.Errorf("recovery: restored postgres pool is required")
	}
	if err := pool.Ping(ctx); err != nil {
		return PostgresValidation{}, fmt.Errorf("recovery: restored postgres unreachable: %w", err)
	}

	tables, err := tenantTables(ctx, pool)
	if err != nil {
		return PostgresValidation{}, err
	}
	if len(tables) == 0 {
		return PostgresValidation{}, fmt.Errorf("recovery: no tenant-scoped tables discovered")
	}

	var securityFailures []string
	for _, table := range tables {
		if !table.RLSEnabled {
			securityFailures = append(securityFailures, table.Name+":rls-disabled")
		}
		if !table.RLSForced {
			securityFailures = append(securityFailures, table.Name+":rls-not-forced")
		}
		if !table.OwnerBypass {
			securityFailures = append(securityFailures, table.Name+":owner-bypass-missing")
		}
	}
	if len(securityFailures) > 0 {
		sort.Strings(securityFailures)
		return PostgresValidation{}, fmt.Errorf("recovery: restored RLS invariants failed: %s", strings.Join(securityFailures, ", "))
	}

	contamination, err := tenantContamination(ctx, pool, tables)
	if err != nil {
		return PostgresValidation{}, err
	}
	if len(contamination) > 0 {
		sort.Strings(contamination)
		return PostgresValidation{}, fmt.Errorf("recovery: tenant contamination detected: %s", strings.Join(contamination, ", "))
	}

	integrity, err := integrityEvidence(ctx, pool)
	if err != nil {
		return PostgresValidation{}, err
	}

	return PostgresValidation{
		IntegrityEvidence: integrity,
		SecurityEvidence:  fmt.Sprintf("%d tenant tables have RLS enabled+forced and owner_bypass", len(tables)),
		TenantEvidence:    fmt.Sprintf("%d tenant tables contain no NULL tenant_id rows", len(tables)),
	}, nil
}

type tenantTable struct {
	Name        string
	RLSEnabled  bool
	RLSForced   bool
	OwnerBypass bool
}

func tenantTables(ctx context.Context, pool *pgxpool.Pool) ([]tenantTable, error) {
	rows, err := pool.Query(ctx, `
SELECT c.relname,
       c.relrowsecurity,
       c.relforcerowsecurity,
       EXISTS (
           SELECT 1 FROM pg_policies p
           WHERE p.schemaname = n.nspname
             AND p.tablename = c.relname
             AND p.policyname = 'owner_bypass'
       )
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND a.attname = 'tenant_id'
  AND NOT a.attisdropped
ORDER BY c.relname`)
	if err != nil {
		return nil, fmt.Errorf("recovery: enumerate tenant tables: %w", err)
	}
	defer rows.Close()

	var result []tenantTable
	for rows.Next() {
		var table tenantTable
		if err := rows.Scan(&table.Name, &table.RLSEnabled, &table.RLSForced, &table.OwnerBypass); err != nil {
			return nil, fmt.Errorf("recovery: scan tenant table: %w", err)
		}
		result = append(result, table)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recovery: enumerate tenant tables: %w", err)
	}
	return result, nil
}

func tenantContamination(ctx context.Context, pool *pgxpool.Pool, tables []tenantTable) ([]string, error) {
	var findings []string
	for _, table := range tables {
		// Table names come only from pg_catalog and are quoted before interpolation.
		query := `SELECT count(*) FROM ` + quoteIdentifier(table.Name) + ` WHERE tenant_id IS NULL`
		var count int64
		if err := pool.QueryRow(ctx, query).Scan(&count); err != nil {
			return nil, fmt.Errorf("recovery: inspect tenant table %s: %w", table.Name, err)
		}
		if count > 0 && !allowsGlobalRows(table.Name) {
			findings = append(findings, fmt.Sprintf("%s:%d-null-tenant-rows", table.Name, count))
		}
	}
	return findings, nil
}

func integrityEvidence(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var invalidConstraints int64
	if err := pool.QueryRow(ctx, `
SELECT count(*)
FROM pg_constraint
WHERE connamespace = 'public'::regnamespace
  AND NOT convalidated`).Scan(&invalidConstraints); err != nil {
		return "", fmt.Errorf("recovery: inspect constraints: %w", err)
	}
	if invalidConstraints != 0 {
		return "", fmt.Errorf("recovery: %d unvalidated constraints after restore", invalidConstraints)
	}

	var migrations int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		return "", fmt.Errorf("recovery: migration ledger unavailable: %w", err)
	}
	if migrations == 0 {
		return "", fmt.Errorf("recovery: migration ledger is empty")
	}
	return fmt.Sprintf("all constraints validated; %d migration records restored", migrations), nil
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

// Some platform/global tables intentionally use tenant_id NULL for operator-wide rows.
// The allowlist is explicit so a newly introduced nullable tenant table fails closed.
func allowsGlobalRows(table string) bool {
	switch table {
	case "content_packages", "content_artifacts", "content_lifecycle_audit", "authority_policies", "retention_policy", "feature_flags":
		return true
	default:
		return false
	}
}
