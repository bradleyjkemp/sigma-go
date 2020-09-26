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
}

// Implements a simple bucketed count
func (i *inMemory) count(ctx context.Context, groupBy sigma.GroupedByValues) float64 {
	i.Lock()
	defer i.Unlock()
	c, ok := i.counts[groupBy.Key()]
	if !ok {
		c = slidingstatistics.Count(i.timeframe)
		i.counts[groupBy.Key()] = c
	}

	return float64(c.Increment())
}

func InMemory(timeframe time.Duration) []sigma.EvaluatorOption {
	i := &inMemory{
		timeframe: timeframe,
		counts:    map[string]*slidingstatistics.Counter{},
	}

	return []sigma.EvaluatorOption{
		sigma.CountImplementation(i.count),
	}
}
