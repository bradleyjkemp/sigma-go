package aggregators

import (
	"context"
	"sync"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/internal/slidingstatistics"
)

type inMemory struct {
	sync.Mutex
	timeframe time.Duration
	counts    map[string]*slidingstatistics.Counter
	averages  map[string]*slidingstatistics.Averager
	sums      map[string]*slidingstatistics.Counter
}

func (i *inMemory) count(ctx context.Context, groupBy sigma.GroupedByValues) float64 {
	i.Lock()
	defer i.Unlock()
	c, ok := i.counts[groupBy.Key()]
	if !ok {
		c = slidingstatistics.Count(i.timeframe)
		i.counts[groupBy.Key()] = c
	}

	return float64(c.IncrementN(time.Now(), 1))
}

func (i *inMemory) average(ctx context.Context, groupBy sigma.GroupedByValues, value float64) float64 {
	i.Lock()
	defer i.Unlock()
	a, ok := i.averages[groupBy.Key()]
	if !ok {
		a = slidingstatistics.Average(i.timeframe)
		i.averages[groupBy.Key()] = a
	}

	return a.Average(time.Now(), value)
}

func (i *inMemory) sum(ctx context.Context, groupBy sigma.GroupedByValues, value float64) float64 {
	i.Lock()
	defer i.Unlock()
	a, ok := i.sums[groupBy.Key()]
	if !ok {
		a = slidingstatistics.Count(i.timeframe)
		i.sums[groupBy.Key()] = a
	}

	return a.IncrementN(time.Now(), value)
}

func InMemory(timeframe time.Duration) []sigma.EvaluatorOption {
	i := &inMemory{
		timeframe: timeframe,
		counts:    map[string]*slidingstatistics.Counter{},
	}

	return []sigma.EvaluatorOption{
		sigma.CountImplementation(i.count),
		sigma.SumImplementation(i.sum),
		sigma.AverageImplementation(i.average),
	}
}
