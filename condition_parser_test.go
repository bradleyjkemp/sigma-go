package sigma

import (
	"reflect"
	"testing"
)

func TestParseCondition(t *testing.T) {
	tt := []struct {
		condition string
		parsed    Condition
	}{
		{"a and b", Condition{Search: And{SearchIdentifier{"a"}, SearchIdentifier{"b"}}}},
		{"a or b", Condition{Search: Or{SearchIdentifier{"a"}, SearchIdentifier{"b"}}}},
		{"a and b or c", Condition{Search: Or{And{SearchIdentifier{"a"}, SearchIdentifier{"b"}}, SearchIdentifier{"c"}}}},
		{"a or b and c", Condition{Search: Or{SearchIdentifier{"a"}, And{SearchIdentifier{"b"}, SearchIdentifier{"c"}}}}},
		{"a and b and c", Condition{Search: And{SearchIdentifier{"a"}, SearchIdentifier{"b"}, SearchIdentifier{"c"}}}},
		{"a | count(b) > 0", Condition{Search: SearchIdentifier{"a"}, Aggregation: Comparison{Func: Count{Field: "b"}, Op: GreaterThan, Threshold: 0}}},
		{"a | count(b) >= 0", Condition{Search: SearchIdentifier{"a"}, Aggregation: Comparison{Func: Count{Field: "b"}, Op: GreaterThanEqual, Threshold: 0}}},
		{"note and pad", Condition{Search: And{SearchIdentifier{"note"}, SearchIdentifier{"pad"}}}},
	}

	for _, tc := range tt {
		t.Run(tc.condition, func(t *testing.T) {
			condition, err := ParseCondition(tc.condition)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(condition, tc.parsed) {
				t.Fatalf("%+v not equal %+v", condition, tc.parsed)
			}
		})
	}
}
