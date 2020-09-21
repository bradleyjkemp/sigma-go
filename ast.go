package sigma

import (
	"fmt"

	"github.com/bradleyjkemp/sigma-go/internal/grammar"
)

type Condition struct {
	Search      SearchExpr
	Aggregation *Aggregation
}

type SearchExpr interface {
	searchExpr()
}

type BoolExpr interface {
	boolExpr()
}

type And struct {
	Left, Right SearchExpr
}

func (And) searchExpr() {}

type Or struct {
	Left, Right SearchExpr
}

func (Or) searchExpr() {}

type Not struct {
	Expr SearchExpr
}

func (Not) searchExpr() {}

type OneOfIdentifier struct {
	Ident SearchIdentifier
}

func (OneOfIdentifier) boolExpr() {}

func (OneOfIdentifier) searchExpr() {}

type AllOfIdentifier struct {
	Ident SearchIdentifier
}

func (AllOfIdentifier) searchExpr() {}

func (AllOfIdentifier) boolExpr() {}

type AllOfPattern struct {
	Pattern SearchIdenfifierPattern
}

func (AllOfPattern) searchExpr() {}

func (AllOfPattern) boolExpr() {}

type OneOfPattern struct {
	Pattern SearchIdenfifierPattern
}

func (OneOfPattern) searchExpr() {}

func (OneOfPattern) boolExpr() {}

type OneOfThem struct{}

func (OneOfThem) searchExpr() {}

func (OneOfThem) boolExpr() {}

type AllOfThem struct{}

func (AllOfThem) searchExpr() {}

func (AllOfThem) boolExpr() {}

type SearchIdentifier struct {
	Name string
}

func (SearchIdentifier) searchExpr() {}

func (SearchIdentifier) boolExpr() {}

type SearchIdenfifierPattern struct {
	Pattern string
}

func (SearchIdenfifierPattern) searchExpr() {}

type ComparisonOp string

var (
	Equal            ComparisonOp = "="
	NotEqual         ComparisonOp = "!="
	LessThan         ComparisonOp = "<"
	LessThanEqual    ComparisonOp = "<="
	GreaterThan      ComparisonOp = ">"
	GreaterThanEqual ComparisonOp = ">="
)

type AggregationFunction string

var (
	Count AggregationFunction = "count"
	Min   AggregationFunction = "min"
	Max   AggregationFunction = "max"
	Avg   AggregationFunction = "avg"
	Sum   AggregationFunction = "sum"
)

type Aggregation struct {
	Function   AggregationFunction
	Field      string
	GroupedBy  string
	Comparison ComparisonOp
	Value      int
}

func searchToAST(node interface{}) SearchExpr {
	switch n := node.(type) {
	case grammar.Disjunction:
		if n.Right == nil {
			return searchToAST(n.Left)
		}

		return Or{
			Left:  searchToAST(n.Left),
			Right: searchToAST(*n.Right),
		}

	case grammar.Conjunction:
		if n.Right == nil {
			return searchToAST(n.Left)
		}

		return And{
			Left:  searchToAST(n.Left),
			Right: searchToAST(*n.Right),
		}

	case grammar.Term:
		switch {
		case n.Negated != nil:
			return Not{Expr: searchToAST(*n.Negated)}

		case n.Identifer != nil:
			return SearchIdentifier{Name: *n.Identifer}

		case n.Subexpression != nil:
			return searchToAST(*n.Subexpression)

		case n.OneAllOf != nil:
			o := n.OneAllOf
			switch {
			case o.ALlOfThem:
				return AllOfThem{}

			case o.OneOfThem:
				return OneOfThem{}

			case o.AllOfIdentifier != nil:
				return AllOfIdentifier{
					Ident: SearchIdentifier{Name: *o.AllOfIdentifier},
				}

			case o.OneOfIdentifier != nil:
				return OneOfIdentifier{
					Ident: SearchIdentifier{Name: *o.OneOfIdentifier},
				}

			case o.AllOfPattern != nil:
				return AllOfPattern{
					Pattern: SearchIdenfifierPattern{Pattern: *o.AllOfPattern},
				}

			case o.OneOfPattern != nil:
				return OneOfPattern{
					Pattern: SearchIdenfifierPattern{Pattern: *o.OneOfPattern},
				}
			default:
				panic("invalid term type: all fields nil")
			}

		default:
			panic("invalid term")
		}

	default:
		panic(fmt.Sprintf("unhandled node type %T", node))
	}
}

func aggregationToAST(agg *grammar.Aggregation) *Aggregation {
	if agg == nil {
		return nil
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
		panic(fmt.Sprintf("unknown operation %v", agg.Comparison))
	}

	var function AggregationFunction
	switch {
	case agg.Function.Count:
		function = Count
	case agg.Function.Min:
		function = Min
	case agg.Function.Max:
		function = Max
	case agg.Function.Avg:
		function = Avg
	case agg.Function.Sum:
		function = Sum
	default:
		panic("unknown aggregation function")
	}

	return &Aggregation{
		Function:   function,
		Field:      agg.AggregationField,
		GroupedBy:  agg.GroupField,
		Comparison: operation,
		Value:      agg.Value,
	}
}
