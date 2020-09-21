package sigma

import (
	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"github.com/bradleyjkemp/sigma-go/internal/grammar"
)

var (
	searchExprLexer = lexer.Must(lexer.Regexp(`(?P<Keyword>(?i)(1 of them)|(all of them)|(1 of)|(all of))` +
		`|(?P<Operator>(?i)and|or|not|[()])` +
		`|(?P<SearchIdentifierPattern>\*?[a-zA-Z_]+\*[a-zA-Z0-9_*]*)` +
		`|(?P<SearchIdentifier>[a-zA-Z_][a-zA-Z0-9_]*)` +
		`|(?P<ComparisonOperation>=|!=|<|<=|>|>=)` +
		`|(?P<ComparisonValue>[1-9][0-9]*)` +
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

	return Condition{
		Search:      searchToAST(root.Search),
		Aggregation: aggregationToAST(root.Aggregation),
	}, nil
}
