package sigma

func FuzzRuleParser(data []byte) int {
	_, err := ParseRule(data)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzConditionParser(data []byte) int {
	_, err := ParseCondition(string(data))
	if err != nil {
		return 0
	}
	return 1
}

func FuzzConfigParser(data []byte) int {
	_, err := ParseConfig(data)
	if err != nil {
		return 0
	}
	return 1
}
