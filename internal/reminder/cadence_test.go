package reminder

import "testing"

func TestIntervalForLadder(t *testing.T) {
	r := DefaultRules
	cases := []struct{ days, want int }{
		{200, 0}, // no cadence yet — milestones only
		{90, 0},
		{60, 0},
		{46, 0},
		{45, 5}, // enters the 45-day rung
		{31, 5},
		{30, 3}, // tightens
		{11, 3},
		{10, 1}, // daily
		{1, 1},
		{0, 1},
		{-1, 1}, // expired keeps nagging daily
		{-30, 1},
	}
	for _, c := range cases {
		if got := r.IntervalFor(c.days); got != c.want {
			t.Errorf("IntervalFor(%d) = %d, want %d", c.days, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	got, err := Parse("30:3,10:1,45:5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10:1,30:3,45:5" {
		t.Errorf("expected sorted ascending, got %s", got.String())
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, spec := range []string{"45", "45:0", "45:x", "x:5", "45:5,45:3"} {
		if _, err := Parse(spec, DefaultRules); err == nil {
			t.Errorf("Parse(%q) should have failed", spec)
		}
	}
}

func TestParseEmptyFallsBackToDefault(t *testing.T) {
	got, err := Parse("  ", DefaultRules)
	if err != nil || got.String() != DefaultRules.String() {
		t.Errorf("empty spec should yield defaults, got %v (%v)", got, err)
	}
}
