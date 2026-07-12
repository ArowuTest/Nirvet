-- 0103_disclosure_closure_narrative.sql
-- Reviewer RM-1 (customer read-model Slice A landing): the disclosure flag governs not just root_cause but ALL
-- free-text, analyst-authored CASE-009 closure/PIR fields — root_cause, impact, actions_taken, lessons_learned.
-- All four are required at closure (incident/transitions.go) and written for the INTERNAL post-incident review;
-- they can name internal detail (tooling, vendors, our own detection gaps), so they must be withheld from the
-- customer by default and disclosed only on operator opt-in. Rename the column to reflect the broadened,
-- fail-closed (default false) semantics. Disposition (a bounded enum), SLA fields, status, and the
-- visibility='customer' timeline remain unconditionally customer-safe.
ALTER TABLE disclosure_policy RENAME COLUMN disclose_root_cause TO disclose_closure_narrative;
