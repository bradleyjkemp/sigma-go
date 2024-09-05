package evaluator

import (
	"context"
	aho_corasick "github.com/BobuSumisu/aho-corasick"
	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"
	"regexp"
	"strings"
	"unsafe"
)

// ForRules compiles a set of rule evaluators which are evaluated together allowing for use of
// more efficient string matching algorithms
func ForRules(rules []sigma.Rule, options ...Option) RuleEvaluatorBundle {
	if len(rules) == 0 {
		return RuleEvaluatorBundle{}
	}

	bundle := RuleEvaluatorBundle{
		ahocorasick: map[string]ahocorasickSearcher{},
	}

	values := map[string][]string{}

	for _, rule := range rules {
		e := ForRule(rule, options...)
		bundle.evaluators = append(bundle.evaluators, e)
		bundle.caseSensitive = e.caseSensitive

		for _, search := range rule.Detection.Searches {
			for _, matcher := range search.EventMatchers {
				for _, fieldMatcher := range matcher {
					contains := false
					regex := false
					for _, modifier := range fieldMatcher.Modifiers {
						if modifier == "contains" {
							contains = true
						}
						if modifier == "re" {
							regex = true
						}
					}
					switch {
					case contains: // add all values to the needle set
						for _, value := range fieldMatcher.Values {
							if value == nil {
								continue
							}
							stringValue := modifiers.CoerceString(value)
							if !bundle.caseSensitive {
								stringValue = strings.ToLower(stringValue)
							}
							values[fieldMatcher.Field] = append(values[fieldMatcher.Field], stringValue)
						}
					case regex: // get "necessary" substrings and add to the needle set
						for _, value := range fieldMatcher.Values {
							ss, caseInsensitive, _ := regexStrings(modifiers.CoerceString(value)) // todo: benchmark this, should save the result?
							for _, s := range ss {
								if caseInsensitive {
									s = strings.ToLower(s)
								}
								values[fieldMatcher.Field] = append(values[fieldMatcher.Field], s)
							}
						}
					}

				}
			}
		}
	}

	for field, fieldValues := range values {
		bundle.ahocorasick[field] = ahocorasickSearcher{
			Trie:     aho_corasick.NewTrieBuilder().AddStrings(fieldValues).Build(),
			patterns: fieldValues,
		}
	}
	return bundle
}

type RuleEvaluatorBundle struct {
	ahocorasick   map[string]ahocorasickSearcher
	evaluators    []*RuleEvaluator
	caseSensitive bool
}

type ahocorasickSearcher struct {
	*aho_corasick.Trie
	patterns []string
}

func (a *ahocorasickContains) getResults(field, s string, caseSensitive bool) map[string]bool {
	as := a.matchers[field]
	key := unsafe.StringData(s) // using the underlying []byte pointer means we only compute results once per interned string
	result, ok := a.results[field][key]
	if ok {
		return result
	}

	// haven't already computed this
	if !caseSensitive {
		s = strings.ToLower(s)
	}
	results := map[string]bool{}
	if _, ok := a.results[field]; !ok {
		a.results[field] = map[*byte]map[string]bool{}
	}
	a.results[field][key] = results
	for _, match := range as.MatchString(s) {
		// TODO: is match.MatchString equivalent to matcher.patterns[match.Pattern()]?
		a.results[field][key][match.MatchString()] = true
	}
	return results
}

type RuleResult struct {
	Result
	sigma.Rule
}

func (bundle RuleEvaluatorBundle) Matches(ctx context.Context, event Event) ([]RuleResult, error) {
	if len(bundle.evaluators) == 0 {
		return nil, nil
	}

	// copy the current rule comparators
	comparators := map[string]modifiers.Comparator{}
	for name, comparator := range bundle.evaluators[0].comparators {
		comparators[name] = comparator
	}

	// override the contains comparator to use our custom one
	contains := &ahocorasickContains{
		matchers:      bundle.ahocorasick,
		caseSensitive: bundle.caseSensitive,
		results:       map[string]map[*byte]map[string]bool{},
	}
	comparators["contains"] = contains
	comparators["re"] = &ahocorasickRe{
		contains,
	}

	ruleresults := []RuleResult{}
	errs := []error{}
	for _, rule := range bundle.evaluators {
		result, err := rule.matches(ctx, event, comparators)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ruleresults = append(ruleresults, RuleResult{
			Result: result,
			Rule:   rule.Rule,
		})
	}
	return ruleresults, nil
}

type ahocorasickContains struct {
	caseSensitive bool
	modifiers.Comparator
	matchers map[string]ahocorasickSearcher
	results  map[string]map[*byte]map[string]bool
}

func (a *ahocorasickContains) MatchesField(field string, actual any, expected any) (bool, error) {
	if expected == "" {
		// compatability with old |contains behaviour
		// possibly a bug?
		return true, nil
	}

	results := a.getResults(field, modifiers.CoerceString(actual), a.caseSensitive)

	needle := modifiers.CoerceString(expected)
	if !a.caseSensitive {
		// when operating in case-insensitive mode, search strings must be canonicalised
		// (this is ok because search strings are much smaller than the haystack)
		// TODO: should we just modify the rules in this case? (saving the lower-casing every time)
		needle = strings.ToLower(needle)
	}
	return results[needle], nil
}

type ahocorasickRe struct {
	*ahocorasickContains
}

func (a *ahocorasickRe) MatchesField(field string, actual any, expected any) (bool, error) {
	stringRe := modifiers.CoerceString(expected)
	re, err := regexp.Compile(stringRe) // todo: cache this?
	if err != nil {
		return false, err
	}

	// this function returns a set of simple strings
	// which necessarily appear if the regex matches
	// If none are present in `actual`, we don't need to run the regex
	ss, caseInsensitive, err := regexStrings(stringRe)
	if err != nil {
		return false, err
	}

	haystack := modifiers.CoerceString(actual)
	results := a.getResults(field, haystack, !caseInsensitive)
	found := false
	for _, s := range ss {
		if results[s] {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	// our cheap heuristic says the regex *might* match the string,
	// so we have to now run the full regex
	return re.MatchString(haystack), nil
}
