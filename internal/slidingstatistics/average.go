package slidingstatistics

import (
	"sync"
	"time"
)

type Averager struct {
	mu      sync.Mutex
	counter *Counter
	summer  *Counter
}

// NewLimiter creates a new limiter, and returns a function to stop
// the possible sync behaviour within the current window.
func Average(size time.Duration) *Averager {
	return &Averager{
		counter: Count(size),
		summer:  Count(size),
	}
}

func (lim *Averager) Average(now time.Time, value float64) float64 {
	lim.mu.Lock()
	defer lim.mu.Unlock()

	estimatedCount := lim.counter.IncrementN(now, 1)
	estimatedSum := lim.summer.IncrementN(now, value)
	return estimatedSum / estimatedCount
}
