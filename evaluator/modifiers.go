package evaluator

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"reflect"
	"regexp"
	"strings"
)

type valueComparator func(actual interface{}, expected interface{}) (bool, error)

func baseComparator(actual interface{}, expected interface{}) (bool, error) {
	switch {
	case actual == nil && expected == "null":
		// special case: "null" should match the case where a field isn't present (and so actual is nil)
		return true, nil
	default:
		// The Sigma spec defines that by default comparisons are case-insensitive
		return strings.EqualFold(fmt.Sprint(actual), fmt.Sprint(expected)), nil
	}
}

type valueModifier func(next valueComparator) valueComparator

var modifiers = map[string]valueModifier{
	"contains": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return strings.Contains(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(expected))), nil
		}
	},
	"endswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return strings.HasSuffix(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(expected))), nil
		}
	},
	"startswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			return strings.HasPrefix(strings.ToLower(fmt.Sprint(actual)), strings.ToLower(fmt.Sprint(expected))), nil
		}
	},
	"base64": func(next valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			return next(actual, base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(expected))))
		}
	},
	"re": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			re, err := regexp.Compile(fmt.Sprint(expected))
			if err != nil {
				return false, err
			}

			return re.MatchString(fmt.Sprint(actual)), nil
		}
	},
	"cidr": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			_, cidr, err := net.ParseCIDR(fmt.Sprint(expected))
			if err != nil {
				return false, err
			}

			ip := net.ParseIP(fmt.Sprint(actual))
			return cidr.Contains(ip), nil
		}
	},
	"gt": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected interface{}) (bool, error) {
			actual, expected, err := coerceNumeric(actual, expected)
			if err != nil {
				return false, err
			}

			switch actual.(type) {
			case int:
				return actual.(int) > expected.(int), nil
			case float64:
				return actual.(float64) > expected.(float64), nil
			default:
				return false, fmt.Errorf("internal, please report! coerceNumeric returned unexpected types %T and %T", actual, expected)
			}
		}
	},
}

// coerceNumeric makes both operands into the widest possible number of the same type
func coerceNumeric(left, right interface{}) (interface{}, interface{}, error) {
	leftV := reflect.ValueOf(left)
	leftType := reflect.ValueOf(left).Type()
	rightV := reflect.ValueOf(right)
	rightType := reflect.ValueOf(right).Type()

	switch {
	// Both integers or both floats? Return directly
	case leftType.Kind() == reflect.Int && rightType.Kind() == reflect.Int:
		fallthrough
	case leftType.Kind() == reflect.Float64 && rightType.Kind() == reflect.Float64:
		return left, right, nil

	// Mixed integer, float? Return two floats
	case leftType.Kind() == reflect.Int && rightType.Kind() == reflect.Float64:
		fallthrough
	case leftType.Kind() == reflect.Float64 && rightType.Kind() == reflect.Int:
		floatType := reflect.TypeOf(float64(0))
		return leftV.Convert(floatType).Interface(), rightV.Convert(floatType).Interface(), nil

	// One or more strings? Parse and recurse.
	// We use `yaml.Unmarshal` to parse the string because it's a cheat's way of parsing either an integer or a float
	case leftType.Kind() == reflect.String:
		var leftParsed interface{}
		if err := yaml.Unmarshal([]byte(left.(string)), &leftParsed); err != nil {
			return nil, nil, err
		}
		return coerceNumeric(leftParsed, right)
	case rightType.Kind() == reflect.String:
		var rightParsed interface{}
		if err := yaml.Unmarshal([]byte(right.(string)), &rightParsed); err != nil {
			return nil, nil, err
		}
		return coerceNumeric(left, rightParsed)

	default:
		return nil, nil, fmt.Errorf("cannot coerce %T and %T to numeric", left, right)
	}
}
