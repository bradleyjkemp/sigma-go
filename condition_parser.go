package sigma

import (
	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"github.com/bradleyjkemp/sigma-go/internal/grammar"
)

var (
	searchExprLexer = lexer.Must(lexer.Regexp(`(?P<Keyword>(?i)(1 of them)|(all of them)|(1 of)|(all of))` +
		`|(?P<SearchIdentifierPattern>\*?[a-zA-Z_]+(?:[a-zA-Z0-9_]*_)*[a-zA-Z0-9]*\*)` + // Adjusted pattern to catch multiple underscores which is present upstream
		`|(?P<SearchIdentifier>[a-zA-Z_][a-zA-Z0-9_]*)` + 
		`|(?P<Operator>(?i)and|or|not|[()])` + // TODO: this never actually matches anything because they get matched as a SearchIdentifier instead. However this isn't currently a problem because we don't parse anything in the Grammar as an Operator (we just use string constants which don't care about Operator vs SearchIdentifier)
		`|(?P<ComparisonOperation>=|!=|<=|>=|<|>)` +
		`|(?P<ComparisonValue>0|[1-9][0-9]*)` +
		`|(?P<Pipe>[|])` +
		`|(\s+)`,
	))

	searchExprParser = participle.MustBuild(
		&grammar.Condition{},
		participle.Lexer(searchExprLexer),
		participle.CaseInsensitive("Keyword", "Operator"),
	)
)

// Parses the Sigma condition syntax
func ParseCondition(input string) (Condition, error) {
	root := grammar.Condition{}
	if err := searchExprParser.ParseString(input, &root); err != nil {
		return Condition{}, err
	}

	search, err := searchToAST(root.Search)
	if err != nil {
		return Condition{}, err
	}
	aggregation, err := aggregationToAST(root.Aggregation)
	if err != nil {
		return Condition{}, err
	}
	return Condition{
		Search:      search,
		Aggregation: aggregation,
	}, nil
}
