package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestFuzzGenStringBoundary(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "username", Type: "string", Source: "http_query", MaxLen: 255},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzUsername") {
		t.Error("missing FuzzUsername function")
	}
	if !strings.Contains(out, `f.Add("")`) {
		t.Error("missing empty string seed")
	}
	if !strings.Contains(out, `f.Add("a")`) {
		t.Error("missing single char seed")
	}
	if !strings.Contains(out, "254") {
		t.Error("missing off-by-one below max length (254)")
	}
	if !strings.Contains(out, "255") {
		t.Error("missing max length seed (255)")
	}
	if !strings.Contains(out, "256") {
		t.Error("missing off-by-one above max length (256)")
	}
}

func TestFuzzGenIntBoundary(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "age", Type: "int", Source: "http_query", Min: 0, Max: 150},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzAge") {
		t.Error("missing FuzzAge function")
	}
	if !strings.Contains(out, "int64(0)") {
		t.Error("missing min seed int64(0)")
	}
	if !strings.Contains(out, "int64(150)") {
		t.Error("missing max seed int64(150)")
	}
	if !strings.Contains(out, "int64(-1)") {
		t.Error("missing off-by-one below min int64(-1)")
	}
	if !strings.Contains(out, "int64(151)") {
		t.Error("missing off-by-one above max int64(151)")
	}
}

func TestFuzzGenUintBoundary(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "port", Type: "uint", Source: "http_query", Min: 1, Max: 65535},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzPort") {
		t.Error("missing FuzzPort function")
	}
	if !strings.Contains(out, "uint64(0)") {
		t.Error("missing uint64(0) seed")
	}
	if !strings.Contains(out, "uint64(1)") {
		t.Error("missing min seed uint64(1)")
	}
	if !strings.Contains(out, "uint64(65535)") {
		t.Error("missing max seed uint64(65535)")
	}
	if !strings.Contains(out, "uint64(65536)") {
		t.Error("missing off-by-one above max uint64(65536)")
	}
}

func TestFuzzGenFloatBoundary(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "score", Type: "float64", Source: "http_query", Min: 0, Max: 100},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzScore") {
		t.Error("missing FuzzScore function")
	}
	if !strings.Contains(out, "float64(0)") {
		t.Error("missing min seed float64(0)")
	}
	if !strings.Contains(out, "float64(100)") {
		t.Error("missing max seed float64(100)")
	}
	if !strings.Contains(out, "float64(-1)") {
		t.Error("missing off-by-one below min float64(-1)")
	}
	if !strings.Contains(out, "float64(101)") {
		t.Error("missing off-by-one above max float64(101)")
	}
}

func TestFuzzGenMultipleTypes(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "username", Type: "string", Source: "http_query", MaxLen: 100},
		{Name: "age", Type: "int", Source: "http_query", Min: 0, Max: 200},
		{Name: "port", Type: "uint", Source: "env_var", Min: 1, Max: 65535},
		{Name: "score", Type: "float64", Source: "http_query", Min: 0, Max: 100},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	for _, want := range []string{"FuzzUsername", "FuzzAge", "FuzzPort", "FuzzScore"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s function in output", want)
		}
	}

	// Verify we have 4 fuzz functions
	count := strings.Count(out, "func Fuzz")
	if count != 4 {
		t.Errorf("want 4 fuzz functions, got %d", count)
	}
}

func TestFuzzGenWriter(t *testing.T) {
	var buf strings.Builder
	entries := []BoundaryEntry{
		{
			Name:       "token",
			Type:       "string",
			Source:     "http_header",
			MaxLen:     64,
			FuzzInputs: []string{"<script>alert(1)</script>", "' OR 1=1 --"},
		},
	}
	WriteFuzzTests(&buf, entries)
	out := buf.String()

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzToken") {
		t.Error("missing FuzzToken function")
	}
	if !strings.Contains(out, "<script>") {
		t.Error("missing XSS payload in seed corpus")
	}
	if !strings.Contains(out, "OR 1=1") {
		t.Error("missing SQLi payload in seed corpus")
	}
}

func TestFuzzGenEmpty(t *testing.T) {
	out := GenerateFuzzTests(nil)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("empty entry list should still produce valid Go: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "package boundaryguard_test") {
		t.Error("missing package declaration")
	}
}

func TestFuzzGenFuncNameSanitization(t *testing.T) {
	entries := []BoundaryEntry{
		{Name: "user_name", Type: "string", MaxLen: 50},
		{Name: "api-key", Type: "string", MaxLen: 128},
		{Name: "DB.host", Type: "string", MaxLen: 255},
	}
	out := GenerateFuzzTests(entries)

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "fuzz_test.go", out, parser.AllErrors)
	if err != nil {
		t.Fatalf("generated code does not parse: %v\ncode:\n%s", err, out)
	}

	if !strings.Contains(out, "FuzzUserName") {
		t.Error("expected underscore to be converted to CamelCase")
	}
	if !strings.Contains(out, "FuzzApiKey") {
		t.Error("expected hyphen to be converted to CamelCase")
	}
	if !strings.Contains(out, "FuzzDBHost") {
		t.Error("expected dot to be converted to CamelCase")
	}
}
