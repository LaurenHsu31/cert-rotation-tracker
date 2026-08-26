// Package reminder holds the escalating notification cadence: as a certificate
// gets closer to expiry, the same alert repeats more often.
//
// This is a second, independent layer on top of the per-certificate milestone
// thresholds (reminder_days). Milestones fire ONCE each as they are crossed
// ("90 days left", "60 days left"); the cadence then keeps nagging on a fixed
// interval that shortens as the deadline approaches. A certificate is alerted
// on a given day if either layer says so — but never more than one alert per
// certificate per scan.
package reminder

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Rule says: once days-remaining drops to WithinDays or below, repeat the
// alert every EveryDays days.
type Rule struct {
	WithinDays int `json:"within_days"`
	EveryDays  int `json:"every_days"`
}

// Rules is an escalation ladder, kept sorted by WithinDays ascending so the
// most urgent matching rule is found first.
type Rules []Rule

// DefaultRules is the shipped ladder: every 5 days under 45, every 3 days
// under 30, daily under 10 (and once expired).
var DefaultRules = Rules{
	{WithinDays: 10, EveryDays: 1},
	{WithinDays: 30, EveryDays: 3},
	{WithinDays: 45, EveryDays: 5},
}

// Parse reads a "45:5,30:3,10:1" spec (within:every, comma separated). An
// empty or wholly invalid spec yields def.
func Parse(spec string, def Rules) (Rules, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return def, nil
	}
	var out Rules
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		within, every, ok := strings.Cut(part, ":")
		if !ok {
			return def, fmt.Errorf("escalation rule %q must be within:every", part)
		}
		w, err := strconv.Atoi(strings.TrimSpace(within))
		if err != nil || w < 0 {
			return def, fmt.Errorf("escalation rule %q: bad threshold", part)
		}
		e, err := strconv.Atoi(strings.TrimSpace(every))
		if err != nil || e < 1 {
			return def, fmt.Errorf("escalation rule %q: interval must be >= 1 day", part)
		}
		if seen[w] {
			return def, fmt.Errorf("escalation rule %q: duplicate threshold %d", part, w)
		}
		seen[w] = true
		out = append(out, Rule{WithinDays: w, EveryDays: e})
	}
	if len(out) == 0 {
		return def, nil
	}
	out.normalize()
	return out, nil
}

func (r Rules) normalize() {
	sort.Slice(r, func(i, j int) bool { return r[i].WithinDays < r[j].WithinDays })
}

// IntervalFor returns how often to repeat an alert for a certificate with
// daysRemaining left, or 0 when no cadence applies yet (milestones only).
// The tightest matching rule wins, so an expired certificate (negative days)
// inherits the most aggressive interval on the ladder.
func (r Rules) IntervalFor(daysRemaining int) int {
	for _, rule := range r { // ascending: first match is the most urgent
		if daysRemaining <= rule.WithinDays {
			return rule.EveryDays
		}
	}
	return 0
}

// String renders the ladder back into its config form.
func (r Rules) String() string {
	parts := make([]string, len(r))
	for i, rule := range r {
		parts[i] = fmt.Sprintf("%d:%d", rule.WithinDays, rule.EveryDays)
	}
	return strings.Join(parts, ",")
}

// Describe renders a human sentence for notification bodies, e.g.
// "repeats every 3 days at this urgency".
func Describe(interval int) string {
	switch {
	case interval <= 0:
		return ""
	case interval == 1:
		return "repeats daily until rotated"
	default:
		return fmt.Sprintf("repeats every %d days until rotated", interval)
	}
}
