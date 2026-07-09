package ingestion_test

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/ingestion"
)

func TestNormalizationConfidence(t *testing.T) {
	// A full canonical mapping scores 100.
	full := ingestion.IngestInput{
		ClassName: "Malware", ActorRef: "user:a", Action: "execute", Outcome: "blocked",
		ActivityName: "process_create", Data: map[string]any{"mitre": []string{"T1059"}},
	}
	if c := ingestion.NormalizationConfidence(full); c != 100 {
		t.Fatalf("full mapping want 100, got %d", c)
	}
	// Nothing mapped → 0 (the strongest drift signal).
	if c := ingestion.NormalizationConfidence(ingestion.IngestInput{Data: map[string]any{}}); c != 0 {
		t.Fatalf("empty want 0, got %d", c)
	}
	// Only class_name (30) + an entity ref (25) = 55.
	partial := ingestion.IngestInput{ClassName: "x", TargetRef: "host:h", Data: map[string]any{}}
	if c := ingestion.NormalizationConfidence(partial); c != 55 {
		t.Fatalf("partial want 55, got %d", c)
	}
	// nil Data must not panic.
	_ = ingestion.NormalizationConfidence(ingestion.IngestInput{ClassName: "x"})
}

func TestDefaultNormSettings(t *testing.T) {
	d := ingestion.DefaultNormSettings()
	if d.MinConfidence != 50 || d.WindowDays != 7 {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}
