-- CEL expression detection rules (SRS §6.6, pluggable DSLs). A rule is either
-- condition-based (all/any predicates, native + Sigma import) OR a CEL expression;
-- expression takes precedence when non-empty. Existing rules default to '' (native).
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS expression text NOT NULL DEFAULT '';
