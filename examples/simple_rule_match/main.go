package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

func main() {
	//
	// Load the Sigma rule (simplified representation here)
	sigmaRule := `
title: Okta Application Modified or Deleted
id: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
status: test
description: Detects when an application is modified or deleted.
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/12
modified: 2022/10/09
tags:
  - attack.impact
logsource:
  product: okta
  service: okta
detection:
  selection:
    eventtype:
      - application.lifecycle.update
      - application.lifecycle.delete
  condition: selection
falsepositives:
  - Unknown

level: medium

  `
	// Parse the Sigma rule
	rule, err := sigma.ParseRule([]byte(sigmaRule))
	if err != nil {
		log.Fatalf("Failed to parse Sigma rule: %v", err)
	}

	// Query Okta logs (simplified, you'll need to implement actual API querying)
	oktaEvents := queryOktaLogs()

	// Rules need to be wrapped in an evaluator.
	// This is also where (if needed) you provide functions implementing the count, max, etc. aggregation functions
	e := evaluator.ForRule(rule)

	// Evaluate each Okta event against the Sigma rule
	for _, event := range oktaEvents {
		matches, err := e.Matches(context.Background(), event)
		if err != nil {
			log.Printf("Error evaluating rule: %v", err)
			continue
		}
		if matches.Match {
			fmt.Println("Detected an application modification or deletion event:", event)
			// Implement your detection handling logic here (e.g., alerting)
		}
	}
}

// queryOktaLogs simulates querying Okta logs. Replace with actual API calls.
func queryOktaLogs() []map[string]interface{} {
	// This is a simplified example. You should replace this function with one
	// that makes HTTP requests to Okta's system log API and parses the response.
	// See https://developer.okta.com/docs/reference/api/system-log/ for details.
	return []map[string]interface{}{
		{"eventtype": "application.lifecycle.update", "details": "Application updated"},
		// Add more events as needed
	}
}
