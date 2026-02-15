package main

import "testing"

func TestScanGoHTTPBoundaries(t *testing.T) {
	code := "package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n" +
		"\tname := r.URL.Query().Get(\"username\")\n" +
		"\ttok := r.Header.Get(\"Authorization\")\n" +
		"\tdb := os.Getenv(\"DB_URL\")\n}"
	bs := ScanContent(code, "handler.go", ".go")
	if len(bs) != 3 {
		t.Fatalf("want 3 boundaries, got %d", len(bs))
	}
	assertBoundary(t, bs[0], "username", "http_query", "URL Query")
	assertBoundary(t, bs[1], "Authorization", "http_header", "HTTP Header")
	assertBoundary(t, bs[2], "DB_URL", "env_var", "Env Var")
}

func TestScanPythonFlask(t *testing.T) {
	code := "from flask import request\n" +
		"name = request.args.get('username')\n" +
		"key = os.getenv(\"API_KEY\")\n"
	bs := ScanContent(code, "app.py", ".py")
	if len(bs) != 2 {
		t.Fatalf("want 2 boundaries, got %d", len(bs))
	}
	assertBoundary(t, bs[0], "username", "http_query", "Flask/Django")
	assertBoundary(t, bs[1], "API_KEY", "env_var", "Env Var")
}

func TestScanJavaScript(t *testing.T) {
	code := "app.get('/api', (req, res) => {\n" +
		"  const id = req.params.userId\n" +
		"  const s = process.env.SECRET_KEY\n" +
		"})\n"
	bs := ScanContent(code, "server.js", ".js")
	if len(bs) != 2 {
		t.Fatalf("want 2 boundaries, got %d", len(bs))
	}
	assertBoundary(t, bs[0], "userId", "http_query", "Express")
	assertBoundary(t, bs[1], "SECRET_KEY", "env_var", "Env Var")
}

func TestTypeScriptSharedPatterns(t *testing.T) {
	code := "const q = req.query.search\n"
	bs := ScanContent(code, "api.ts", ".ts")
	if len(bs) != 1 {
		t.Fatalf("want 1 boundary, got %d", len(bs))
	}
	assertBoundary(t, bs[0], "search", "http_query", "Express")
}

func TestValidationRulesPerType(t *testing.T) {
	for _, typ := range []string{"http_query", "http_header", "env_var"} {
		v := genValidation(typ)
		if len(v) < 3 {
			t.Errorf("%s: want >=3 rules, got %d", typ, len(v))
		}
	}
}

func TestFuzzPayloadGeneration(t *testing.T) {
	for _, typ := range []string{"http_query", "http_header", "env_var"} {
		f := genFuzz(typ)
		if len(f) < 5 {
			t.Errorf("%s: want >=5 fuzz inputs, got %d", typ, len(f))
		}
	}
}

func TestNoMatchOnIrrelevantCode(t *testing.T) {
	code := "fmt.Println(\"hello world\")\nx := 42\n"
	bs := ScanContent(code, "main.go", ".go")
	if len(bs) != 0 {
		t.Errorf("want 0 boundaries on clean code, got %d", len(bs))
	}
}

func assertBoundary(t *testing.T, b Boundary, wantVar, wantType, wantSrc string) {
	t.Helper()
	if b.Variable != wantVar {
		t.Errorf("variable: want %q, got %q", wantVar, b.Variable)
	}
	if b.Type != wantType {
		t.Errorf("type: want %q, got %q", wantType, b.Type)
	}
	if b.Source != wantSrc {
		t.Errorf("source: want %q, got %q", wantSrc, b.Source)
	}
	if len(b.Validation) == 0 {
		t.Error("expected non-empty validation rules")
	}
	if len(b.FuzzInputs) == 0 {
		t.Error("expected non-empty fuzz inputs")
	}
}
