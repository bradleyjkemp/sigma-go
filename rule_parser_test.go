package sigma

import (
	"github.com/google/go-cmp/cmp/cmpopts"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestParseRule(t *testing.T) {
	err := filepath.Walk("./testdata/", func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".rule.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".rule.yml"), func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseRule(contents)
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			cupaloy.New(cupaloy.SnapshotSubdirectory("testdata")).SnapshotT(t, rule)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalRule(t *testing.T) {
	err := filepath.Walk("./testdata/", func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".rule.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".rule.yml"), func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseRule(contents)
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			// Create a new temporary file in our testing temp directory
			stream, err := os.CreateTemp(t.TempDir(), filepath.Base(path))
			if err != nil {
				t.Fatalf("error creating temp rule file: %v", err)
			}
			defer os.Remove(stream.Name())
			defer stream.Close()

			// Save the rule to a temporary file
			encoder := yaml.NewEncoder(stream)
			if err := encoder.Encode(&rule); err != nil {
				t.Fatalf("error encoding rule to file: %v", err)
			}

			// Return to the beginning of the stream
			stream.Seek(0, os.SEEK_SET)

			// Re-read the rule from the newly serialized file
			var rule_copy Rule
			decoder := yaml.NewDecoder(stream)
			if err := decoder.Decode(&rule_copy); err != nil {
				t.Fatalf("error decoding rule copy: %v", err)
			}

			if !cmp.Equal(rule, rule_copy, cmpopts.IgnoreUnexported(Condition{}, FieldMatcher{}, Search{})) {
				t.Fatalf("rule and marshalled copy are not equal")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Timeframes use a number followed by a unit: s, m, h or d.
// See the timeframe section of the Sigma specification:
// https://github.com/SigmaHQ/sigma-specification/blob/v1.0.5/Sigma_specification.md#timeframe
func TestParseRule_Timeframe(t *testing.T) {
	tests := []struct {
		timeframe string
		want      time.Duration
		wantErr   bool
	}{
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"1h", time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"d", 0, true},
		{"-1d", 0, true},
		{"1.5d", 0, true},
		{"5x", 0, true},
		{"[5m]", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.timeframe, func(t *testing.T) {
			rule, err := ParseRule([]byte(`
title: timeframe
logsource:
  product: linux
detection:
  selection:
    foo: bar
  timeframe: ` + tt.timeframe + `
  condition: selection | count() > 5
`))
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("expected an error parsing timeframe %q, got %v", tt.timeframe, rule.Detection.Timeframe)
			case tt.wantErr:
				return
			case err != nil:
				t.Fatalf("error parsing rule: %v", err)
			}

			if rule.Detection.Timeframe != tt.want {
				t.Errorf("Timeframe = %v, want %v", rule.Detection.Timeframe, tt.want)
			}
			// the rest of the detection must still be parsed
			if _, ok := rule.Detection.Searches["selection"]; !ok || len(rule.Detection.Searches) != 1 {
				t.Errorf("expected exactly one search called selection, got %v", rule.Detection.Searches)
			}
			if len(rule.Detection.Conditions) != 1 || rule.Detection.Conditions[0].Aggregation == nil {
				t.Errorf("expected one condition with an aggregation, got %v", rule.Detection.Conditions)
			}

			// and must survive a marshal/unmarshal round trip
			out, err := yaml.Marshal(rule)
			if err != nil {
				t.Fatalf("error marshalling rule: %v", err)
			}
			roundTripped, err := ParseRule(out)
			if err != nil {
				t.Fatalf("error parsing marshalled rule: %v\n%s", err, out)
			}
			if roundTripped.Detection.Timeframe != tt.want {
				t.Errorf("Timeframe after round trip = %v, want %v", roundTripped.Detection.Timeframe, tt.want)
			}
		})
	}
}
