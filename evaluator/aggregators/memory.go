package aggregators

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/bradleyjkemp/sigma-go/internal/slidingstatistics"
)

type inMemory struct {
	sync.Mutex
	timeframe time.Duration
	counts    map[string]*slidingstatistics.Counter
	distinct  map[string]*distinctCounter
	averages  map[string]*slidingstatistics.Averager
	sums      map[string]*slidingstatistics.Counter
}

func (i *inMemory) count(ctx context.Context, groupBy evaluator.GroupedByValues) (float64, error) {
	i.Lock()
	defer i.Unlock()
	c, ok := i.counts[groupBy.Key()]
	if !ok {
		c = slidingstatistics.Count(i.timeframe)
		i.counts[groupBy.Key()] = c
	}

	return float64(c.IncrementN(time.Now(), 1)), nil
}

func (i *inMemory) countDistinct(ctx context.Context, groupBy evaluator.GroupedByValues, value interface{}) (float64, error) {
	i.Lock()
	defer i.Unlock()
	d, ok := i.distinct[groupBy.Key()]
	if !ok {
		d = &distinctCounter{timeframe: i.timeframe, lastSeen: map[string]time.Time{}}
		i.distinct[groupBy.Key()] = d
	}

	return float64(d.Add(time.Now(), value)), nil
}

// distinctCounter counts the distinct values seen within a sliding timeframe
type distinctCounter struct {
	timeframe time.Duration
	lastSeen  map[string]time.Time
	seen      []distinctObservation // in the order they were added so that expiring old values doesn't need to scan lastSeen
}

type distinctObservation struct {
	value string
	at    time.Time
}

// Add records value (unless it is nil, i.e. the field was missing) and returns the number of distinct values seen in the timeframe ending at now
func (d *distinctCounter) Add(now time.Time, value interface{}) int {
	if value != nil {
		v := fmt.Sprint(value)
		d.lastSeen[v] = now
		d.seen = append(d.seen, distinctObservation{value: v, at: now})
	}

	expired := 0
	for _, o := range d.seen {
		if now.Sub(o.at) <= d.timeframe {
			break
		}
		expired++
		// only forget the value if it hasn't been seen again since
		if d.lastSeen[o.value] == o.at {
			delete(d.lastSeen, o.value)
		}
	}
	d.seen = d.seen[expired:]
	return len(d.lastSeen)
}

func (i *inMemory) average(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	a, ok := i.averages[groupBy.Key()]
	if !ok {
		a = slidingstatistics.Average(i.timeframe)
		i.averages[groupBy.Key()] = a
	}

	return a.Average(time.Now(), value), nil
}

func (i *inMemory) sum(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	a, ok := i.sums[groupBy.Key()]
	if !ok {
		a = slidingstatistics.Count(i.timeframe)
		i.sums[groupBy.Key()] = a
	}

	return a.IncrementN(time.Now(), value), nil
}

func InMemory(timeframe time.Duration) []evaluator.Option {
	i := &inMemory{
		timeframe: timeframe,
		counts:    map[string]*slidingstatistics.Counter{},
		distinct:  map[string]*distinctCounter{},
	}

	return []evaluator.Option{
		evaluator.CountImplementation(i.count),
		evaluator.CountDistinctImplementation(i.countDistinct),
		evaluator.SumImplementation(i.sum),
		evaluator.AverageImplementation(i.average),
	}
}
