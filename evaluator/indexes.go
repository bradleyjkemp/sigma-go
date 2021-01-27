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

			// If the mapping declares conditions then AND them with the current one
			rule.indexConditions = append(rule.indexConditions, logsource.Conditions)
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

// RelevantToIndex calculates whether a rule is applicable to an event based on:
// 	* Whether the rule has been configured with a config file that matches the eventIndex
//	* Whether the event matches the conditions from the config file
func (rule RuleEvaluator) RelevantToEvent(eventIndex string, event Event) bool {
	matchedIndex := false
	for _, index := range rule.indexes {
		if index == eventIndex { // TODO: this also needs to support wildcards
			matchedIndex = true
			break
		}
	}
	if !matchedIndex {
		return false
	}

	// The event *does* come from an index we're interested in but we still
	// need to check for any value constraints that have been specified
	// TODO: this doesn't yet support the logsourcemerging option to choose between ANDing/ORing these conditions
	for _, condition := range rule.indexConditions {
		if !rule.evaluateSearch(condition, event) {
			return false
		}
	}
	return true
}
