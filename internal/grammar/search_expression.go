package grammar

type Condition struct {
	Search      Disjunction  `@@`
	Aggregation *Aggregation `("|" @@)?`
}

type Disjunction struct {
	Nodes []*Conjunction `@@ ("or" @@)*`
}

type Conjunction struct {
	Nodes []*Term `@@ ("and" @@)*`
}

type Term struct {
	Negated       *Term        `"not" @@`
	OneAllOf      *OneAllOf    `| @@`
	Identifer     *string      `| @SearchIdentifier`
	Subexpression *Disjunction `| "(" @@ ")"`
}

type OneAllOf struct {
	OneOfIdentifier *string `"1 of" @SearchIdentifier`
	AllOfIdentifier *string `| "all of" @SearchIdentifier`
	OneOfPattern    *string `| "1 of" @SearchIdentifierPattern`
	AllOfPattern    *string `| "all of" @SearchIdentifierPattern`
	OneOfThem       bool    `| @("1 of them")`
	ALlOfThem       bool    `| @("all of them")`
}
