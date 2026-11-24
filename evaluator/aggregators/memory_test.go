package aggregators

import (
	"context"
	"testing"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

func TestInMemory_CountDistinct(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: count distinct
logsource:
  product: test
detection:
  selection:
    action: login_failed
  timeframe: 1h
  condition: selection | count(user) by src_ip > 2
`))
	if err != nil {
		t.Fatalf("error parsing rule: %v", err)
	}
	e := evaluator.ForRule(rule, InMemory(rule.Detection.Timeframe)...)

	tests := []struct {
		user  interface{}
		srcIP string
		want  bool
	}{
		{"alice", "10.0.0.1", false},
		{"alice", "10.0.0.1", false},
		{"bob", "10.0.0.1", false},
		{"carol", "10.0.0.2", false},
		{nil, "10.0.0.1", false},
		{"dave", "10.0.0.1", true},
		{"erin", "10.0.0.2", false},
	}
	for i, tt := range tests {
		event := map[string]interface{}{"action": "login_failed", "src_ip": tt.srcIP}
		if tt.user != nil {
			event["user"] = tt.user
		}
		result, err := e.Matches(context.Background(), event)
		if err != nil {
			t.Fatalf("event %d: error evaluating rule: %v", i, err)
		}
		if result.Match != tt.want {
			t.Errorf("event %d (%v): Match = %v, want %v", i, event, result.Match, tt.want)
		}
	}
}

func TestDistinctCounter(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	d := &distinctCounter{timeframe: time.Minute, lastSeen: map[string]time.Time{}}

	tests := []struct {
		offset time.Duration
		value  interface{}
		want   int
	}{
		{0, "a", 1},
		{10 * time.Second, "b", 2},
		{20 * time.Second, "a", 2},
		{30 * time.Second, 1, 3},
		{30 * time.Second, "1", 3}, // values are compared by their string representation
		{40 * time.Second, nil, 3}, // missing values aren't counted
		{75 * time.Second, "c", 3}, // b has expired, a was seen again at 20s
		{150 * time.Second, nil, 0},
	}
	for _, tt := range tests {
		if got := d.Add(start.Add(tt.offset), tt.value); got != tt.want {
			t.Errorf("Add(+%v, %v) = %d, want %d", tt.offset, tt.value, got, tt.want)
		}
	}
}
