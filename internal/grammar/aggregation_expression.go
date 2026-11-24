package grammar

type Aggregation struct {
	Function         AggregationFunction `parser:"@@"`
	AggregationField string              `parser:"(\"(\" (@SearchIdentifier)? \")\")?"`
	GroupField       string              `parser:"(\"by\" @SearchIdentifier)?"`
	Comparison       *ComparisonOp       `parser:"(@@"`
	Threshold        float64             `parser:"@ComparisonValue)?"`
}

type AggregationFunction struct {
	Count bool `parser:"@\"count\""`
	Min   bool `parser:"| @\"min\""`
	Max   bool `parser:"| @\"max\""`
	Avg   bool `parser:"| @\"avg\""`
	Sum   bool `parser:"| @\"sum\""`
}

type ComparisonOp struct {
	Equal            bool `parser:"@\"=\""`
	NotEqual         bool `parser:"| @\"!=\""`
	LessThan         bool `parser:"| @\"<\""`
	LessThanEqual    bool `parser:"| @\"<=\""`
	GreaterThan      bool `parser:"| @\">\""`
	GreaterThanEqual bool `parser:"| @\">=\""`
}
