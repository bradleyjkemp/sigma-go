package evaluator

func (rule *RuleEvaluator) calculateFieldMappings() {
	if rule.config == nil {
		return
	}

	mappings := map[string][]string{}

	for _, config := range rule.config {
		for field, mapping := range config.FieldMappings {
			// TODO: trim duplicates and only care about fields that are actually checked by this rule
			mappings[field] = append(mappings[field], mapping.TargetNames...)
		}
	}

	rule.fieldmappings = mappings
}
