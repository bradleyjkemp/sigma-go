package slidingstatistics

import (
	"fmt"
	"testing"
	"time"
)

func TestSlidingAverage(t *testing.T) {
	c := Average(time.Minute)

	// Create a "now" that's always nicely within a window
	now := time.Now().Truncate(time.Minute).Add(time.Second)

	// Within a time window, the average should be perfect
	for i := 1; i <= 10; i++ {
		now = now.Add(time.Second)
		actual := c.Average(now, float64(i))

		var expected float64
		for j := 1; j <= i; j++ {
			expected += float64(j)
		}
		expected = expected / float64(i)

		if expected != actual {
			t.Fatal("average should be exact within time window")
		}
	}

	// now advance 1 minute so we're into the sliding window behaviour
	now = now.Add(80 * time.Second)
	average := c.Average(now, 10)
	fmt.Println(average)
	now = now.Add(30 * time.Second)
	average = c.Average(now, 10)
	fmt.Println(average)
}
