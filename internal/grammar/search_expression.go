package grammar

type Condition struct {
	Search      Disjunction  `parser:"@@"`
	Aggregation *Aggregation `parser:"(\"|\" @@)?"`
}

type Disjunction struct {
	Nodes []*Conjunction `parser:"@@ (\"or\" @@)*"`
}

type Conjunction struct {
	Nodes []*Term `parser:"@@ (\"and\" @@)*"`
}

type Term struct {
	Negated       *Term        `parser:"\"not\" @@"`
	OneAllOf      *OneAllOf    `parser:"| @@"`
	Identifer     *string      `parser:"| @SearchIdentifier"`
	Subexpression *Disjunction `parser:"| \"(\" @@ \")\""`
}

type OneAllOf struct {
	OneOfIdentifier *string `parser:"\"1 of\" @SearchIdentifier"`
	AllOfIdentifier *string `parser:"| \"all of\" @SearchIdentifier"`
	OneOfPattern    *string `parser:"| \"1 of\" @SearchIdentifierPattern"`
	AllOfPattern    *string `parser:"| \"all of\" @SearchIdentifierPattern"`
	OneOfThem       bool    `parser:"| @(\"1 of them\")"`
	ALlOfThem       bool    `parser:"| @(\"all of them\")"`
}
