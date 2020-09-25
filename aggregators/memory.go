package aggregators

import (
	"context"
	"sync"

	"github.com/bradleyjkemp/sigma-go"
)

type inMemoryValue struct {
	value int
}

type inMemory struct {
	sync.Mutex
	counts map[string]inMemoryValue
}

// Implements a simple bucketed count
func (i *inMemory) count(ctx context.Context, key sigma.AggregationKey) int {
	i.Lock()
	defer i.Unlock()
	c := i.counts[key.String()]
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
