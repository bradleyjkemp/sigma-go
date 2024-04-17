package evaluator

import (
	"context"
	"github.com/bradleyjkemp/sigma-go"
	"testing"
)

func TestCoerceNumeric_NilLoop(t *testing.T) {
	// https://github.com/bradleyjkemp/sigma-go/issues/42

	r, _ := sigma.ParseRule([]byte(`title: Test Sigma Rule
id: 123
status: experimental
description: Crash the evaluator
date: 2024/03/27
detection:
  cond1:
    - receivedByte|gte: 0
  cond2:
    - deviceAddress|gte: 172.16.0.0
  condition: cond1 and cond2
level: low`))
	e := ForRule(r)

	_, _ = e.Matches(context.Background(), map[string]interface{}{
		"receivedBytes": 25,
		"deviceAddress": "172.16.2.2",
	})
}
