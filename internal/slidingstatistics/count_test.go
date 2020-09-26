package slidingstatistics

import (
	"testing"
	"time"
)

func TestSlidingCount(t *testing.T) {
	c := Count(time.Minute)

	// Create a "now" that's always nicely within a window
	now := time.Now().Truncate(time.Minute).Add(time.Second)

	for i := 1; i <= 10; i++ {
		now = now.Add(time.Second)
		count := c.IncrementN(now, 1)
		if float64(i) != count {
			t.Fatal("count should be equal to i")
		}
	}

	// now advance 1 minute so we're into the sliding window behaviour
	now = now.Add(80 * time.Second)
	count := c.IncrementN(now, 1)
	if !(count > 0 && count < 10) {
		t.Fatal("count should be in the range [1,10)")
	}

}
