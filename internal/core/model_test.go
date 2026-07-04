package core

import "testing"

func TestSummaryMaxSeverity(t *testing.T) {
	s := Summarize([]Finding{
		{Severity: SeverityLow},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
	})
	if s.Total != 3 {
		t.Fatalf("total = %d, want 3", s.Total)
	}
	if got := s.MaxSeverity(); got != SeverityHigh {
		t.Fatalf("max severity = %s, want high", got)
	}
}

func TestParseSeverity(t *testing.T) {
	if got := ParseSeverity("Moderate"); got != SeverityMedium {
		t.Fatalf("ParseSeverity(Moderate) = %s, want medium", got)
	}
}
