package evaluator

// RelevantToIndex calculates whether this rule is applicable to a given index.
// Only applicable if a config file has been loaded otherwise it always returns false.
func (rule *RuleEvaluator) calculateIndexes() {
	if rule.config == nil {
		return
	}

	var indexes []string

	category := rule.Logsource.Category
	product := rule.Logsource.Product
	service := rule.Logsource.Service

	for _, config := range rule.config {
		matched := false
		for _, logsource := range config.Logsources {
			// If this mapping is not relevant, skip it
			switch {
			case logsource.Category != "" && logsource.Category != category:
				continue
			case logsource.Product != "" && logsource.Product != product:
				continue
			case logsource.Service != "" && logsource.Service != service:
				continue
			}

			matched = true
			// LogsourceMappings can specify rewrite rules that change the effective Category, Product, and Service of a rule.
			// These then get interpreted by later configs.
			if logsource.Rewrite.Category != "" {
				category = logsource.Rewrite.Category
			}
			if logsource.Rewrite.Product != "" {
				product = logsource.Rewrite.Product
			}
			if logsource.Rewrite.Service != "" {
				service = logsource.Rewrite.Service
			}

			// If the mapping has indexes then append them to the possible ones
			indexes = append(indexes, logsource.Index...)
		}

		if !matched && config.DefaultIndex != "" {
			indexes = append(indexes, config.DefaultIndex)
		}
	}

	rule.indexes = indexes
}

func (rule RuleEvaluator) Indexes() []string {
	return rule.indexes
}

func (rule RuleEvaluator) RelevantToIndex(eventIndex string) bool {
	// Now finally actually check if the eventIndex matches this rule
	for _, index := range rule.indexes {
		if index == eventIndex { // TODO: this also needs to support wildcards
			return true
		}
	}

	return false
}
