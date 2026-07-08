package safe

import "testing"

// TestDoRecovers: a panicking fn does not propagate, and a normal fn runs to completion.
func TestDoRecovers(t *testing.T) {
	// Must not panic out of Do.
	Do(nil, "panics", func() { panic("boom") })

	ran := false
	Do(nil, "normal", func() { ran = true })
	if !ran {
		t.Fatal("Do must run the function when it does not panic")
	}

	// A recovered panic must not prevent the NEXT Do from running (loop continues).
	Do(nil, "again", func() { panic("boom2") })
	after := false
	Do(nil, "after", func() { after = true })
	if !after {
		t.Fatal("Do must keep working after a recovered panic")
	}
}
