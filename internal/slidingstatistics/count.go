package slidingstatistics

import (
	"sync"
	"time"
)

type Counter struct {
	size  time.Duration
	limit int64

	mu sync.Mutex

	curr countWindow
	prev countWindow
}

// NewLimiter creates a new limiter, and returns a function to stop
// the possible sync behaviour within the current window.
func Count(size time.Duration) *Counter {
	return &Counter{
		size: size,
		curr: countWindow{},
		prev: countWindow{},
	}
}

// Size returns the time duration of one window size. Note that the size
// is defined to be read-only, if you need to change the size,
// create a new limiter with a new size instead.
func (lim *Counter) Size() time.Duration {
	return lim.size
}

func (lim *Counter) IncrementN(now time.Time, n float64) float64 {
	lim.mu.Lock()
	defer lim.mu.Unlock()

	lim.advance(now)
	lim.curr.total += n

	elapsed := now.Sub(lim.curr.Start())
	weight := float64(lim.size-elapsed) / float64(lim.size) // TODO: this breaks if provided with a timestamp before the current window start
	return weight*lim.prev.total + lim.curr.total
}

// advance updates the current/previous windows resulting from the passage of time.
func (lim *Counter) advance(now time.Time) {
	// Calculate the start boundary of the expected current-window.
	newCurrStart := now.Truncate(lim.size)

	diffSize := newCurrStart.Sub(lim.curr.Start()) / lim.size
	if diffSize >= 1 {
		// The current-window is at least one-window-size behind the expected one.

		newPrevTotal := float64(0)
		if diffSize == 1 {
			// The new previous-window will overlap with the old current-window,
			// so it inherits the count.
			//
			// Note that the count here may be not accurate, since it is only a
			// SNAPSHOT of the current-window's count, which in itself tends to
			// be inaccurate due to the asynchronous nature of the sync behaviour.
			newPrevTotal = lim.curr.total
		}
		lim.prev.Reset(newCurrStart.Add(-lim.size), newPrevTotal)

		// The new current-window always has zero count.
		lim.curr.Reset(newCurrStart, 0)
	}
}

// countWindow represents a window that ignores sync behavior entirely
// and only stores counters in memory.
type countWindow struct {
	// The start boundary (timestamp in nanoseconds) of the window.
	// [start, start + size)
	start int64

	// The total count of events happened in the window.
	total float64
}

func (w *countWindow) Start() time.Time {
	return time.Unix(0, w.start)
}

func (w *countWindow) Reset(s time.Time, c float64) {
	w.start = s.UnixNano()
	w.total = c
}
