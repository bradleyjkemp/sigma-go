package aggregators

import (
	"context"
	"sync"
	"time"

	"github.com/bradleyjkemp/sigma-go"
)

type inMemoryValue struct {
	value     int
	lastReset time.Time
}

type inMemory struct {
	sync.Mutex
	counts map[string]inMemoryValue
}

// Implements a simple bucketed count
func (i *inMemory) count(ctx context.Context, key sigma.AggregationKey, timeframe time.Duration) int {
	i.Lock()
	defer i.Unlock()
	c, ok := i.counts[key.String()]
	if !ok {
		c = inMemoryValue{
			lastReset: time.Now(),
		}
	}

	if time.Now().Sub(c.lastReset) > timeframe {
		c = inMemoryValue{
			lastReset: time.Now(),
		}
	}

	c.value++
	i.counts[key.String()] = c
	return c.value
}

func InMemory() []sigma.EvaluatorOption {
	i := &inMemory{
		counts: map[string]inMemoryValue{},
	}

	return []sigma.EvaluatorOption{
		sigma.CountFunction(i.count),
	}
}
