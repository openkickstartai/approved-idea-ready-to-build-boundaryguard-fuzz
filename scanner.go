package main

import (
	"os"
	"regexp"
	"strings"
)

type Boundary struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Type       string   `json:"type"`
	Source     string   `json:"source"`
	Variable   string   `json:"variable"`
	Validation []string `json:"validation_rules"`
	FuzzInputs []string `json:"fuzz_inputs"`
}

type rule struct {
	exts   []string
	typ    string
	source string
	re     *regexp.Regexp
	idx    int
}

var rules = []rule{
	{[]string{".go"}, "http_query", "URL Query",
		regexp.MustCompile(`(?:URL\.Query\(\)\.Get|FormValue)\("([^"]+)"\)`), 1},
	{[]string{".go"}, "env_var", "Env Var",
		regexp.MustCompile(`os\.Getenv\("([^"]+)"\)`), 1},
	{[]string{".go"}, "http_header", "HTTP Header",
		regexp.MustCompile(`Header\.Get\("([^"]+)"\)`), 1},
	{[]string{".py"}, "http_query", "Flask/Django",
		regexp.MustCompile(`request\.(?:args|form|json)(?:\.get\(|\.?\[)['"]([\w]+)`), 1},
	{[]string{".py"}, "env_var", "Env Var",
		regexp.MustCompile(`os\.(?:environ\.get|getenv)\(['"]([^'"]+)['"]\)`), 1},
	{[]string{".js", ".ts"}, "http_query", "Express",
		regexp.MustCompile(`req\.(query|params|body)\.(\w+)`), 2},
	{[]string{".js", ".ts"}, "env_var", "Env Var",
		regexp.MustCompile(`process\.env\.(\w+)`), 1},
}

func ScanFile(path, ext string) []Boundary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ScanContent(string(data), path, ext)
}

func ScanContent(content, path, ext string) []Boundary {
	var out []Boundary
	for i, line := range strings.Split(content, "\n") {
		for _, r := range rules {
			if !hasExt(r.exts, ext) {
				continue
			}
			m := r.re.FindStringSubmatch(line)
			if m == nil || r.idx >= len(m) {
				continue
			}
			out = append(out, Boundary{
				File: path, Line: i + 1, Type: r.typ,
				Source: r.source, Variable: m[r.idx],
				Validation: genValidation(r.typ),
				FuzzInputs: genFuzz(r.typ),
			})
		}
	}
	return out
}

func hasExt(exts []string, ext string) bool {
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}

func genValidation(typ string) []string {
	base := []string{"check non-empty", "max length 1024"}
	switch typ {
	case "http_query":
		return append(base, "sanitize HTML entities", "validate against allowlist")
	case "http_header":
		return append(base, "reject CRLF characters", "validate header format")
	case "env_var":
		return append(base, "provide default value", "validate format on startup")
	}
	return base
}

func genFuzz(typ string) []string {
	base := []string{`""`, `"<script>alert(1)</script>"`, `"' OR 1=1--"`, `"A"x10000`}
	switch typ {
	case "http_query":
		return append(base, `"%0d%0aInjected"`, `"{{7*7}}"`, `"../../../etc/passwd"`)
	case "http_header":
		return append(base, `"\r\nX-Injected: true"`, `"bytes(0x00-0xff)"`)
	case "env_var":
		return append(base, `"$(whoami)"`, `"; rm -rf /"`, `"\x00NULL"`)
	}
	return base
}
