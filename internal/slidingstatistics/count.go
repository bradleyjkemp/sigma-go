package slidingstatistics

import (
	"sync"
	"time"
)

// Window represents a fixed-window.
type Window interface {
	// Start returns the start boundary.
	Start() time.Time

	// Count returns the accumulated count.
	Count() int64

	// AddCount increments the accumulated count by n.
	AddCount(n int64)

	// Reset sets the state of the window with the given settings.
	Reset(s time.Time, c int64)

	// Sync tries to exchange data between the window and the central
	// datastore at time now, to keep the window's count up-to-date.
	Sync(now time.Time)
}

type Counter struct {
	size  time.Duration
	limit int64

	mu sync.Mutex

	curr Window
	prev Window
}

// NewLimiter creates a new limiter, and returns a function to stop
// the possible sync behaviour within the current window.
func Count(size time.Duration) *Counter {
	return &Counter{
		size: size,
		curr: &localWindow{},
		prev: &localWindow{},
	}
}

// Size returns the time duration of one window size. Note that the size
// is defined to be read-only, if you need to change the size,
// create a new limiter with a new size instead.
func (lim *Counter) Size() time.Duration {
	return lim.size
}

// Allow is shorthand for AllowN(time.Now(), 1).
func (lim *Counter) Increment() int64 {
	return lim.IncrementN(time.Now(), 1)
}

// AllowN reports whether n events may happen at time now.
func (lim *Counter) IncrementN(now time.Time, n int64) int64 {
	lim.mu.Lock()
	defer lim.mu.Unlock()

	lim.advance(now)
	lim.curr.AddCount(n)

	elapsed := now.Sub(lim.curr.Start())
	weight := float64(lim.size-elapsed) / float64(lim.size) // TODO: this breaks if provided with a timestamp before the current window start
	count := int64(weight*float64(lim.prev.Count())) + lim.curr.Count()

	return count
}

// advance updates the current/previous windows resulting from the passage of time.
func (lim *Counter) advance(now time.Time) {
	// Calculate the start boundary of the expected current-window.
	newCurrStart := now.Truncate(lim.size)

	diffSize := newCurrStart.Sub(lim.curr.Start()) / lim.size
	if diffSize >= 1 {
		// The current-window is at least one-window-size behind the expected one.

		newPrevCount := int64(0)
		if diffSize == 1 {
			// The new previous-window will overlap with the old current-window,
			// so it inherits the count.
			//
			// Note that the count here may be not accurate, since it is only a
			// SNAPSHOT of the current-window's count, which in itself tends to
			// be inaccurate due to the asynchronous nature of the sync behaviour.
			newPrevCount = lim.curr.Count()
		}
		lim.prev.Reset(newCurrStart.Add(-lim.size), newPrevCount)

		// The new current-window always has zero count.
		lim.curr.Reset(newCurrStart, 0)
	}
}

// localWindow represents a window that ignores sync behavior entirely
// and only stores counters in memory.
type localWindow struct {
	// The start boundary (timestamp in nanoseconds) of the window.
	// [start, start + size)
	start int64

	// The total count of events happened in the window.
	count int64
}

func (w *localWindow) Start() time.Time {
	return time.Unix(0, w.start)
}

func (w *localWindow) Count() int64 {
	return w.count
}

func (w *localWindow) AddCount(n int64) {
	w.count += n
}

func (w *localWindow) Reset(s time.Time, c int64) {
	w.start = s.UnixNano()
	w.count = c
}

func (w *localWindow) Sync(now time.Time) {}
