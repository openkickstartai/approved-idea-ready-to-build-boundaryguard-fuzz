package main

import (
	"fmt"
	"io"
	"strings"
	"unicode"
)

// BoundaryEntry represents a discovered input boundary for fuzz test generation.
type BoundaryEntry struct {
	Name       string   // parameter or variable name
	Type       string   // "string", "int", "uint", "float64"
	Source     string   // "http_query", "http_header", "env_var"
	Min        int64    // minimum value for numeric types
	Max        int64    // maximum value for numeric types
	MaxLen     int      // max length for string types
	FuzzInputs []string // additional seed values
}

// GenerateFuzzTests produces a complete Go _test.go file containing native fuzz
// functions for each boundary entry. Seed corpus includes min, max, and off-by-one values.
func GenerateFuzzTests(entries []BoundaryEntry) string {
	var buf strings.Builder
	WriteFuzzTests(&buf, entries)
	return buf.String()
}

// WriteFuzzTests writes generated fuzz test source code to the provided writer.
func WriteFuzzTests(w io.Writer, entries []BoundaryEntry) {
	fmt.Fprintln(w, "package boundaryguard_test")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "import (")
	fmt.Fprintln(w, "\t\"testing\"")
	fmt.Fprintln(w, ")")

	for _, e := range entries {
		fmt.Fprintln(w)
		writeFuzzFunc(w, e)
	}
}

// fuzzFuncName converts a boundary name like "user_name" into "FuzzUserName".
func fuzzFuncName(name string) string {
	var b strings.Builder
	b.WriteString("Fuzz")
	upper := true
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
			upper = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func writeFuzzFunc(w io.Writer, e BoundaryEntry) {
	name := fuzzFuncName(e.Name)
	switch e.Type {
	case "int":
		writeIntFuzz(w, name, e)
	case "uint":
		writeUintFuzz(w, name, e)
	case "float64":
		writeFloatFuzz(w, name, e)
	default:
		writeStringFuzz(w, name, e)
	}
}

func writeStringFuzz(w io.Writer, name string, e BoundaryEntry) {
	fmt.Fprintf(w, "func %s(f *testing.F) {\n", name)
	fmt.Fprintf(w, "\tf.Add(\"\")\n")
	fmt.Fprintf(w, "\tf.Add(\"a\")\n")
	if e.MaxLen > 1 {
		fmt.Fprintf(w, "\tf.Add(string(make([]byte, %d)))\n", e.MaxLen-1)
	}
	if e.MaxLen > 0 {
		fmt.Fprintf(w, "\tf.Add(string(make([]byte, %d)))\n", e.MaxLen)
		fmt.Fprintf(w, "\tf.Add(string(make([]byte, %d)))\n", e.MaxLen+1)
	}
	for _, fi := range e.FuzzInputs {
		fmt.Fprintf(w, "\tf.Add(%q)\n", fi)
	}
	fmt.Fprintf(w, "\tf.Fuzz(func(t *testing.T, v string) {\n")
	fmt.Fprintf(w, "\t\t_ = v\n")
	fmt.Fprintf(w, "\t})\n")
	fmt.Fprintf(w, "}\n")
}

func writeIntFuzz(w io.Writer, name string, e BoundaryEntry) {
	fmt.Fprintf(w, "func %s(f *testing.F) {\n", name)
	fmt.Fprintf(w, "\tf.Add(int64(%d))\n", e.Min)
	fmt.Fprintf(w, "\tf.Add(int64(%d))\n", e.Max)
	fmt.Fprintf(w, "\tf.Add(int64(%d))\n", e.Min-1)
	fmt.Fprintf(w, "\tf.Add(int64(%d))\n", e.Max+1)
	fmt.Fprintf(w, "\tf.Add(int64(0))\n")
	fmt.Fprintf(w, "\tf.Fuzz(func(t *testing.T, v int64) {\n")
	fmt.Fprintf(w, "\t\t_ = v\n")
	fmt.Fprintf(w, "\t})\n")
	fmt.Fprintf(w, "}\n")
}

func writeUintFuzz(w io.Writer, name string, e BoundaryEntry) {
	fmt.Fprintf(w, "func %s(f *testing.F) {\n", name)
	fmt.Fprintf(w, "\tf.Add(uint64(0))\n")
	if e.Min > 0 {
		fmt.Fprintf(w, "\tf.Add(uint64(%d))\n", uint64(e.Min-1))
	}
	fmt.Fprintf(w, "\tf.Add(uint64(%d))\n", uint64(e.Min))
	fmt.Fprintf(w, "\tf.Add(uint64(%d))\n", uint64(e.Max))
	fmt.Fprintf(w, "\tf.Add(uint64(%d))\n", uint64(e.Max)+1)
	fmt.Fprintf(w, "\tf.Fuzz(func(t *testing.T, v uint64) {\n")
	fmt.Fprintf(w, "\t\t_ = v\n")
	fmt.Fprintf(w, "\t})\n")
	fmt.Fprintf(w, "}\n")
}

func writeFloatFuzz(w io.Writer, name string, e BoundaryEntry) {
	minF := float64(e.Min)
	maxF := float64(e.Max)
	fmt.Fprintf(w, "func %s(f *testing.F) {\n", name)
	fmt.Fprintf(w, "\tf.Add(float64(%g))\n", minF)
	fmt.Fprintf(w, "\tf.Add(float64(%g))\n", maxF)
	fmt.Fprintf(w, "\tf.Add(float64(%g))\n", minF-1)
	fmt.Fprintf(w, "\tf.Add(float64(%g))\n", maxF+1)
	fmt.Fprintf(w, "\tf.Add(float64(0))\n")
	fmt.Fprintf(w, "\tf.Fuzz(func(t *testing.T, v float64) {\n")
	fmt.Fprintf(w, "\t\t_ = v\n")
	fmt.Fprintf(w, "\t})\n")
	fmt.Fprintf(w, "}\n")
}
