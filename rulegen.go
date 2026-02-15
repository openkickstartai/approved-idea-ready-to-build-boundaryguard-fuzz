package main

import (
	"fmt"
	"strings"
)

// BoundaryEntry represents a discovered input boundary with its constraints.
type BoundaryEntry struct {
	ParamName    string
	DataType     string   // "string", "int", "enum"
	MaxLength    int      // max string length (0 = no limit)
	MinLength    int      // min string length (0 = no limit)
	MinValue     int64    // integer lower bound
	MaxValue     int64    // integer upper bound
	EnumValues   []string // allowed values for enum validation
	RegexPattern string   // regex pattern the value must match
}

// ValidationRule holds a generated Go validation code snippet.
type ValidationRule struct {
	ParamName string
	RuleType  string // "length", "range", "regex", "enum"
	GoCode    string
}

// GenerateRules produces Go validation code snippets from discovered boundary entries.
func GenerateRules(entries []BoundaryEntry) []ValidationRule {
	var out []ValidationRule
	for _, e := range entries {
		out = append(out, rulesForEntry(e)...)
	}
	return out
}

func rulesForEntry(e BoundaryEntry) []ValidationRule {
	var out []ValidationRule

	switch e.DataType {
	case "string":
		if e.MaxLength > 0 {
			out = append(out, ValidationRule{
				ParamName: e.ParamName,
				RuleType:  "length",
				GoCode: fmt.Sprintf(
					"if len(%s) > %d {\n\treturn fmt.Errorf(\"%s exceeds max length %d\")\n}",
					e.ParamName, e.MaxLength, e.ParamName, e.MaxLength),
			})
		}
		if e.MinLength > 0 {
			out = append(out, ValidationRule{
				ParamName: e.ParamName,
				RuleType:  "length",
				GoCode: fmt.Sprintf(
					"if len(%s) < %d {\n\treturn fmt.Errorf(\"%s must be at least %d characters\")\n}",
					e.ParamName, e.MinLength, e.ParamName, e.MinLength),
			})
		}
	case "int":
		out = append(out, ValidationRule{
			ParamName: e.ParamName,
			RuleType:  "range",
			GoCode: fmt.Sprintf(
				"if %s < %d || %s > %d {\n\treturn fmt.Errorf(\"%s must be between %d and %d\")\n}",
				e.ParamName, e.MinValue, e.ParamName, e.MaxValue,
				e.ParamName, e.MinValue, e.MaxValue),
		})
	}

	// Enum rules apply regardless of DataType (a string or enum field can have allowed values)
	if len(e.EnumValues) > 0 {
		quoted := make([]string, len(e.EnumValues))
		for i, v := range e.EnumValues {
			quoted[i] = fmt.Sprintf("%q", v)
		}
		cases := strings.Join(quoted, ", ")
		display := strings.Join(e.EnumValues, ", ")
		out = append(out, ValidationRule{
			ParamName: e.ParamName,
			RuleType:  "enum",
			GoCode: fmt.Sprintf(
				"switch %s {\ncase %s:\n\t// valid\ndefault:\n\treturn fmt.Errorf(\"%s must be one of [%s]\")\n}",
				e.ParamName, cases, e.ParamName, display),
		})
	}

	// Regex rules
	if e.RegexPattern != "" {
		out = append(out, ValidationRule{
			ParamName: e.ParamName,
			RuleType:  "regex",
			GoCode: fmt.Sprintf(
				"if matched, _ := regexp.MatchString(%q, %s); !matched {\n\treturn fmt.Errorf(\"%s does not match required pattern\")\n}",
				e.RegexPattern, e.ParamName, e.ParamName),
		})
	}

	return out
}
