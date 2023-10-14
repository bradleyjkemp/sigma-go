package sigma

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bradleyjkemp/sigma-go/internal/grammar"
)

type Condition struct {
	node        *yaml.Node      `yaml:",omitempty" json:",omitempty"`
	Search      SearchExpr      `yaml:",omitempty" json:",omitempty"`
	Aggregation AggregationExpr `yaml:",omitempty" json:",omitempty"`
}

func (c Condition) MarshalYAML() (interface{}, error) {
	search := c.Search.toString()
	if c.Aggregation != nil {
		return search + " | " + c.Aggregation.toString(), nil
	} else {
		return search, nil
	}
}

// Position returns the line and column of this Condition in the original input
func (c Condition) Position() (int, int) {
	return c.node.Line - 1, c.node.Column - 1
}

type SearchExpr interface {
	searchExpr()
	toString() string
}

type And []SearchExpr

func (And) searchExpr() {}

func (e And) toString() string {
	if len(e) == 1 {
		return e[0].toString()
	} else {
		converted := make([]string, len(e))
		for idx, sub := range e {
			converted[idx] = sub.toString()
		}
		return "(" + strings.Join(converted, " and ") + ")"
	}
}

type Or []SearchExpr

func (Or) searchExpr() {}

func (e Or) toString() string {
	if len(e) == 1 {
		return e[0].toString()
	} else {
		converted := make([]string, len(e))
		for idx, sub := range e {
			converted[idx] = sub.toString()
		}
		return "(" + strings.Join(converted, " or ") + ")"
	}
}

type Not struct {
	Expr SearchExpr
}

func (e Not) toString() string {
	return "not " + e.Expr.toString()
}

func (Not) searchExpr() {}

type OneOfIdentifier struct {
	Ident SearchIdentifier
}

func (OneOfIdentifier) searchExpr() {}

func (e OneOfIdentifier) toString() string {
	return "1 of " + e.Ident.toString()
}

type AllOfIdentifier struct {
	Ident SearchIdentifier
}

func (AllOfIdentifier) searchExpr() {}

func (e AllOfIdentifier) toString() string {
	return "all of " + e.Ident.toString()
}

type AllOfPattern struct {
	Pattern string
}

func (AllOfPattern) searchExpr() {}

func (e AllOfPattern) toString() string {
	return "all of " + e.Pattern
}

type OneOfPattern struct {
	Pattern string
}

func (OneOfPattern) searchExpr() {}

func (e OneOfPattern) toString() string {
	return "1 of " + e.Pattern
}

type OneOfThem struct{}

func (OneOfThem) searchExpr() {}

func (OneOfThem) toString() string {
	return "1 of them"
}

type AllOfThem struct{}

func (AllOfThem) searchExpr() {}

func (AllOfThem) toString() string {
	return "all of them"
}

type SearchIdentifier struct {
	Name string
}

func (SearchIdentifier) searchExpr() {}

func (e SearchIdentifier) toString() string {
	return e.Name
}

type AggregationExpr interface {
	aggregationExpr()
	toString() string
}

type Near struct {
	Condition SearchExpr
}

func (Near) aggregationExpr() {}

func (n Near) toString() string {
	return "near " + n.Condition.toString()
}

type ComparisonOp string

var (
	Equal            ComparisonOp = "="
	NotEqual         ComparisonOp = "!="
	LessThan         ComparisonOp = "<"
	LessThanEqual    ComparisonOp = "<="
	GreaterThan      ComparisonOp = ">"
	GreaterThanEqual ComparisonOp = ">="
)

type Comparison struct {
	Func      AggregationFunc
	Op        ComparisonOp
	Threshold float64
}

func (Comparison) aggregationExpr() {}

func (e Comparison) toString() string {
	return fmt.Sprintf("%v %v %v", e.Func.toString(), e.Op, e.Threshold)
}

type AggregationFunc interface {
	aggregationFunc()
	toString() string
}

type Count struct {
	Field     string
	GroupedBy string
}

func (Count) aggregationFunc() {}

func (c Count) toString() string {
	result := "count(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

type Min struct {
	Field     string
	GroupedBy string
}

func (Min) aggregationFunc() {}

func (c Min) toString() string {
	result := "min(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

type Max struct {
	Field     string
	GroupedBy string
}

func (Max) aggregationFunc() {}

func (c Max) toString() string {
	result := "max(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

type Average struct {
	Field     string
	GroupedBy string
}

func (Average) aggregationFunc() {}

func (c Average) toString() string {
	result := "avg(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

type Sum struct {
	Field     string
	GroupedBy string
}

func (Sum) aggregationFunc() {}

func (c Sum) toString() string {
	result := "sum(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

func searchToAST(node interface{}) (SearchExpr, error) {
	switch n := node.(type) {
	case grammar.Disjunction:
		if len(n.Nodes) == 1 {
			return searchToAST(*n.Nodes[0])
		}

		or := Or{}
		for _, node := range n.Nodes {
			n, err := searchToAST(*node)
			if err != nil {
				return nil, err
			}
			or = append(or, n)
		}
		return or, nil

	case grammar.Conjunction:
		if len(n.Nodes) == 1 {
			return searchToAST(*n.Nodes[0])
		}

		and := And{}
		for _, node := range n.Nodes {
			n, err := searchToAST(*node)
			if err != nil {
				return nil, err
			}
			and = append(and, n)
		}
		return and, nil

	case grammar.Term:
		switch {
		case n.Negated != nil:
			n, err := searchToAST(*n.Negated)
			if err != nil {
				return nil, err
			}
			return Not{Expr: n}, nil

		case n.Identifer != nil:
			return SearchIdentifier{Name: *n.Identifer}, nil

		case n.Subexpression != nil:
			return searchToAST(*n.Subexpression)

		case n.OneAllOf != nil:
			o := n.OneAllOf
			switch {
			case o.ALlOfThem:
				return AllOfThem{}, nil

			case o.OneOfThem:
				return OneOfThem{}, nil

			case o.AllOfIdentifier != nil:
				return AllOfIdentifier{
					Ident: SearchIdentifier{Name: *o.AllOfIdentifier},
				}, nil

			case o.OneOfIdentifier != nil:
				return OneOfIdentifier{
					Ident: SearchIdentifier{Name: *o.OneOfIdentifier},
				}, nil

			case o.AllOfPattern != nil:
				return AllOfPattern{
					Pattern: *o.AllOfPattern,
				}, nil

			case o.OneOfPattern != nil:
				return OneOfPattern{
					Pattern: *o.OneOfPattern,
				}, nil
			default:
				return nil, fmt.Errorf("invalid term type: all fields nil")
			}

		default:
			return nil, fmt.Errorf("invalid term")
		}

	default:
		return nil, fmt.Errorf("unhandled node type %T", node)
	}
}

func aggregationToAST(agg *grammar.Aggregation) (AggregationExpr, error) {
	if agg == nil {
		return nil, nil
	}

	var function AggregationFunc
	switch {
	case agg.Function.Count:
		function = Count{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Min:
		function = Min{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Max:
		function = Max{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Avg:
		function = Average{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Sum:
		function = Sum{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	default:
		return nil, fmt.Errorf("unknown aggregation function")
	}

	if agg.Comparison == nil {
		return nil, fmt.Errorf("non comparison aggregations not yet supported")
	}

	var operation ComparisonOp
	switch {
	case agg.Comparison.Equal:
		operation = Equal
	case agg.Comparison.NotEqual:
		operation = NotEqual
	case agg.Comparison.LessThan:
		operation = LessThan
	case agg.Comparison.LessThanEqual:
		operation = LessThanEqual
	case agg.Comparison.GreaterThan:
		operation = GreaterThan
	case agg.Comparison.GreaterThanEqual:
		operation = GreaterThanEqual
	default:
		return nil, fmt.Errorf("unknown operation %v", agg.Comparison)
	}

	return Comparison{
		Func:      function,
		Op:        operation,
		Threshold: agg.Threshold,
	}, nil
}
