package sigma

import (
	"fmt"

	"github.com/bradleyjkemp/sigma-go/internal/grammar"
)

type Condition struct {
	Search      SearchExpr
	Aggregation AggregationExpr
}

type SearchExpr interface {
	searchExpr()
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

func (OneOfIdentifier) searchExpr() {}

type AllOfIdentifier struct {
	Ident SearchIdentifier
}

func (AllOfIdentifier) searchExpr() {}

type AllOfPattern struct {
	Pattern SearchIdenfifierPattern
}

func (AllOfPattern) searchExpr() {}

type OneOfPattern struct {
	Pattern SearchIdenfifierPattern
}

func (OneOfPattern) searchExpr() {}

type OneOfThem struct{}

func (OneOfThem) searchExpr() {}

type AllOfThem struct{}

func (AllOfThem) searchExpr() {}

type SearchIdentifier struct {
	Name string
}

func (SearchIdentifier) searchExpr() {}

type SearchIdenfifierPattern struct {
	Pattern string
}

func (SearchIdenfifierPattern) searchExpr() {}

type AggregationExpr interface {
	aggregationExpr()
}

type Near struct {
	Condition SearchExpr
}

func (Near) aggregationExpr() {}

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
	Threshold int
}

func (Comparison) aggregationExpr() {}

type AggregationFunc interface {
	aggregationFunc()
}

type Count struct {
	Field     string
	GroupedBy string
}

func (Count) aggregationFunc() {}

type Min struct {
	Field     string
	GroupedBy string
}

func (Min) aggregationFunc() {}

type Max struct {
	Field     string
	GroupedBy string
}

func (Max) aggregationFunc() {}

type Average struct {
	Field     string
	GroupedBy string
}

func (Average) aggregationFunc() {}

type Sum struct {
	Field     string
	GroupedBy string
}

func (Sum) aggregationFunc() {}

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

func aggregationToAST(agg *grammar.Aggregation) AggregationExpr {
	if agg == nil {
		return nil
	}

	var function AggregationFunc
	switch {
	case agg.Function.Count:
		function = Count{}
	case agg.Function.Min:
		function = Min{}
	case agg.Function.Max:
		function = Max{}
	case agg.Function.Avg:
		function = Average{}
	case agg.Function.Sum:
		function = Sum{}
	default:
		panic("unknown aggregation function")
	}

	if agg.Comparison == nil {
		panic("non comparison aggregations not yet supported")
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

	return Comparison{
		Func:      function,
		Op:        operation,
		Threshold: agg.Threshold,
	}
}
