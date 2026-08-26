package severity

// Level is the urgency classification derived from how many days remain
// before a certificate expires. It is separate from the per-certificate
// reminder thresholds: thresholds decide WHEN a notification fires, Level
// decides how it LOOKS and whether it escalates.
type Level string

const (
	Healthy  Level = "healthy"  // plenty of runway
	Notice   Level = "notice"   // worth noting
	Warning  Level = "warning"  // start paying attention
	Urgent   Level = "urgent"   // act soon
	Critical Level = "critical" // act now
	Expired  Level = "expired"  // already past expiry
)

// Cutoffs are the day boundaries between levels. Sourced from config so
// they can be tuned per deployment without code changes.
type Cutoffs struct {
	Notice   int // e.g. 90
	Warning  int // e.g. 60
	Urgent   int // e.g. 30
	Critical int // e.g. 7
}

// Classify maps a days-remaining value to a Level.
//
//	days > Notice            -> Healthy
//	Warning  < days <= Notice   -> Notice
//	Urgent   < days <= Warning  -> Warning
//	Critical < days <= Urgent   -> Urgent
//	0       <= days <= Critical -> Critical
//	days < 0                 -> Expired
func Classify(daysRemaining int, c Cutoffs) Level {
	switch {
	case daysRemaining < 0:
		return Expired
	case daysRemaining <= c.Critical:
		return Critical
	case daysRemaining <= c.Urgent:
		return Urgent
	case daysRemaining <= c.Warning:
		return Warning
	case daysRemaining <= c.Notice:
		return Notice
	default:
		return Healthy
	}
}

// Rank returns an ordering weight so the most urgent items sort first.
// Higher = more urgent.
func Rank(l Level) int {
	switch l {
	case Expired:
		return 5
	case Critical:
		return 4
	case Urgent:
		return 3
	case Warning:
		return 2
	case Notice:
		return 1
	default:
		return 0
	}
}
