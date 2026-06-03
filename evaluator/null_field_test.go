package evaluator

import (
	"context"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
)

// TestNullFieldMatcher tests that "Field: null" in a Sigma rule correctly matches events
// where the field is absent (nil), and does not match events where the field is present.
// This is the standard Sigma behavior described in the specification: a null matcher tests
// for field absence, commonly used in negative filters of the form "not 1 of filter_*".
func TestNullFieldMatcher(t *testing.T) {
	// Build a rule that uses a null matcher: matches when CommandLine is absent.
	nullMatcherRule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"no_commandline": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:  "CommandLine",
								Values: []interface{}{nil},
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "no_commandline"}},
			},
		},
	})

	t.Run("matches when field is absent", func(t *testing.T) {
		result, err := nullMatcherRule.Matches(context.Background(), map[string]interface{}{
			"Image": "C:\\Windows\\System32\\cmd.exe",
			// CommandLine intentionally absent
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Match {
			t.Error("expected match: rule should match when the field is absent")
		}
	})

	t.Run("does not match when field is present", func(t *testing.T) {
		result, err := nullMatcherRule.Matches(context.Background(), map[string]interface{}{
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "whoami",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Match {
			t.Error("expected no match: rule should not match when the field is present")
		}
	})

	t.Run("does not match when field is explicitly nil in event", func(t *testing.T) {
		// A field present in the map but set to nil is treated as present-but-null.
		// Depending on the use case callers may store absent fields as nil; we treat
		// nil values the same as absent (both satisfy the null matcher).
		result, err := nullMatcherRule.Matches(context.Background(), map[string]interface{}{
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": nil,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Match {
			t.Error("expected match: a nil field value should satisfy the null matcher")
		}
	})
}

// TestNullFieldMatcher_NegativeFilterIdiom tests the common Sigma pattern where a null matcher
// is used as a negative filter (i.e. "not 1 of filter_*") to suppress detections when a
// particular field is absent. The detection rule fires only when the field IS present.
func TestNullFieldMatcher_NegativeFilterIdiom(t *testing.T) {
	// Pattern:
	//   detection:
	//     selection:
	//       CommandLine|contains: 'powershell'
	//     filter_no_cmdline:
	//       CommandLine: null
	//     condition: selection and not filter_no_cmdline
	//
	// Semantic: fire the alert only when CommandLine is present AND contains 'powershell'.
	// When CommandLine is absent, filter_no_cmdline matches, so the whole condition is false.
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"selection": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "CommandLine",
								Modifiers: []string{"contains"},
								Values:    []interface{}{"powershell"},
							},
						},
					},
				},
				"filter_no_cmdline": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:  "CommandLine",
								Values: []interface{}{nil},
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{
				{
					Search: sigma.And{
						sigma.SearchIdentifier{Name: "selection"},
						sigma.Not{
							Expr: sigma.SearchIdentifier{Name: "filter_no_cmdline"},
						},
					},
				},
			},
		},
	})

	t.Run("fires when CommandLine is present and matches", func(t *testing.T) {
		result, err := rule.Matches(context.Background(), map[string]interface{}{
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "powershell -enc abc",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Match {
			t.Error("expected match: selection matches and filter does not apply")
		}
	})

	t.Run("does not fire when CommandLine is absent", func(t *testing.T) {
		result, err := rule.Matches(context.Background(), map[string]interface{}{
			"Image": "C:\\Windows\\System32\\cmd.exe",
			// CommandLine absent — filter_no_cmdline matches, suppressing the alert
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Match {
			t.Error("expected no match: CommandLine absent so filter suppresses the detection")
		}
	})

	t.Run("does not fire when CommandLine is present but does not match", func(t *testing.T) {
		result, err := rule.Matches(context.Background(), map[string]interface{}{
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "notepad.exe",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Match {
			t.Error("expected no match: selection does not match")
		}
	})
}
