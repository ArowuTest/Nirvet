-- 0091_reports_format_pdf.sql — allow 'pdf' as a report export format (§6.13 launch-line, HEAVY tier).
-- The PDF renderer is the fenced, zero-egress pdfrender sub-package. This only widens the format check;
-- JSON/CSV/XLSX are unchanged. Idempotent (drop-if-exists then re-add) so it is from-zero safe.

ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_format_chk;
ALTER TABLE reports ADD CONSTRAINT reports_format_chk CHECK (format IN ('json','csv','xlsx','pdf'));
