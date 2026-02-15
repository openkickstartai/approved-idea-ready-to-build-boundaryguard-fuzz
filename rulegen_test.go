package main

import (
	"strings"
	"testing"
)

func TestRuleGenStringMaxLength(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "username", DataType: "string", MaxLength: 256},
	}
	rules := GenerateRules(entries)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ParamName != "username" {
		t.Errorf("ParamName = %q, want %q", r.ParamName, "username")
	}
	if r.RuleType != "length" {
		t.Errorf("RuleType = %q, want %q", r.RuleType, "length")
	}
	if !strings.Contains(r.GoCode, "len(username) > 256") {
		t.Errorf("GoCode missing max length check: %s", r.GoCode)
	}
	if !strings.Contains(r.GoCode, "return") {
		t.Errorf("GoCode missing return: %s", r.GoCode)
	}
}

func TestRuleGenStringMinAndMaxLength(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "password", DataType: "string", MinLength: 8, MaxLength: 128},
	}
	rules := GenerateRules(entries)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules (max+min), got %d", len(rules))
	}
	if !strings.Contains(rules[0].GoCode, "len(password) > 128") {
		t.Errorf("first rule should check max length: %s", rules[0].GoCode)
	}
	if rules[0].RuleType != "length" {
		t.Errorf("first rule type = %q, want length", rules[0].RuleType)
	}
	if !strings.Contains(rules[1].GoCode, "len(password) < 8") {
		t.Errorf("second rule should check min length: %s", rules[1].GoCode)
	}
	if rules[1].RuleType != "length" {
		t.Errorf("second rule type = %q, want length", rules[1].RuleType)
	}
}

func TestRuleGenIntegerRange(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "age", DataType: "int", MinValue: 0, MaxValue: 150},
	}
	rules := GenerateRules(entries)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ParamName != "age" {
		t.Errorf("ParamName = %q, want %q", r.ParamName, "age")
	}
	if r.RuleType != "range" {
		t.Errorf("RuleType = %q, want %q", r.RuleType, "range")
	}
	if !strings.Contains(r.GoCode, "age < 0") {
		t.Errorf("GoCode missing min bound check: %s", r.GoCode)
	}
	if !strings.Contains(r.GoCode, "age > 150") {
		t.Errorf("GoCode missing max bound check: %s", r.GoCode)
	}
	if !strings.Contains(r.GoCode, "return") {
		t.Errorf("GoCode missing return: %s", r.GoCode)
	}
}

func TestRuleGenEnum(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "status", DataType: "string", EnumValues: []string{"active", "inactive", "banned"}},
	}
	rules := GenerateRules(entries)
	var enumRule *ValidationRule
	for i := range rules {
		if rules[i].RuleType == "enum" {
			enumRule = &rules[i]
			break
		}
	}
	if enumRule == nil {
		t.Fatal("no enum rule generated")
	}
	if enumRule.ParamName != "status" {
		t.Errorf("ParamName = %q, want %q", enumRule.ParamName, "status")
	}
	if !strings.Contains(enumRule.GoCode, "switch status") {
		t.Errorf("GoCode should use switch: %s", enumRule.GoCode)
	}
	for _, val := range []string{`"active"`, `"inactive"`, `"banned"`} {
		if !strings.Contains(enumRule.GoCode, val) {
			t.Errorf("GoCode missing enum value %s: %s", val, enumRule.GoCode)
		}
	}
	if !strings.Contains(enumRule.GoCode, "default:") {
		t.Errorf("GoCode missing default case: %s", enumRule.GoCode)
	}
}

func TestRuleGenEmptyInput(t *testing.T) {
	rules := GenerateRules(nil)
	if len(rules) != 0 {
		t.Fatalf("want 0 rules for nil input, got %d", len(rules))
	}
	rules = GenerateRules([]BoundaryEntry{})
	if len(rules) != 0 {
		t.Fatalf("want 0 rules for empty slice, got %d", len(rules))
	}
}

func TestRuleGenRegex(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "email", DataType: "string", RegexPattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`},
	}
	rules := GenerateRules(entries)
	var regexRule *ValidationRule
	for i := range rules {
		if rules[i].RuleType == "regex" {
			regexRule = &rules[i]
			break
		}
	}
	if regexRule == nil {
		t.Fatal("no regex rule generated")
	}
	if regexRule.ParamName != "email" {
		t.Errorf("ParamName = %q, want %q", regexRule.ParamName, "email")
	}
	if !strings.Contains(regexRule.GoCode, "regexp.MatchString") {
		t.Errorf("GoCode missing regexp.MatchString: %s", regexRule.GoCode)
	}
	if !strings.Contains(regexRule.GoCode, "email") {
		t.Errorf("GoCode missing param reference: %s", regexRule.GoCode)
	}
}

func TestRuleGenMultipleEntries(t *testing.T) {
	entries := []BoundaryEntry{
		{ParamName: "name", DataType: "string", MaxLength: 100},
		{ParamName: "count", DataType: "int", MinValue: 1, MaxValue: 1000},
		{ParamName: "role", DataType: "enum", EnumValues: []string{"admin", "user", "guest"}},
	}
	rules := GenerateRules(entries)
	if len(rules) < 3 {
		t.Fatalf("want at least 3 rules, got %d", len(rules))
	}

	typesSeen := map[string]bool{}
	paramsSeen := map[string]bool{}
	for _, r := range rules {
		typesSeen[r.RuleType] = true
		paramsSeen[r.ParamName] = true
	}
	for _, want := range []string{"length", "range", "enum"} {
		if !typesSeen[want] {
			t.Errorf("missing rule type %q in output", want)
		}
	}
	for _, want := range []string{"name", "count", "role"} {
		if !paramsSeen[want] {
			t.Errorf("missing param %q in output", want)
		}
	}
}
