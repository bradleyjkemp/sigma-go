package grammar

type Aggregation struct {
	Function         AggregationFunction `@@`
	AggregationField string              `("(" (@SearchIdentifier)? ")")?`
	GroupField       string              `("by" @SearchIdentifier)?`
	Comparison       *ComparisonOp       `(@@`
	Threshold        float64             `@ComparisonValue)?`
}

type AggregationFunction struct {
	Count bool `@"count"`
	Min   bool `| @"min"`
	Max   bool `| @"max"`
	Avg   bool `| @"avg"`
	Sum   bool `| @"sum"`
}

type ComparisonOp struct {
	Equal            bool `@"="`
	NotEqual         bool `| @"!="`
	LessThan         bool `| @"<"`
	LessThanEqual    bool `| @"<="`
	GreaterThan      bool `| @">"`
	GreaterThanEqual bool `| @">="`
}
