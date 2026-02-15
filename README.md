# 🛡️ BoundaryGuard

Automatically discover all input boundaries in your code, generate validation rules, and produce targeted fuzz test inputs.

Scans Go, Python, and JS/TS codebases to find where external input enters your application — HTTP parameters, headers, environment variables — then generates security validation rules and fuzz payloads.

## 🚀 Quick Start

```bash
# Install
go install github.com/boundaryguard/boundaryguard@latest

# Scan current directory
boundaryguard --dir .

# JSON output for CI
boundaryguard --dir ./src --format json

# Fail CI on findings
boundaryguard --dir . --fail
```

## Build from Source

```bash
git clone https://github.com/boundaryguard/boundaryguard
cd boundaryguard
go build -o boundaryguard .
go test -v ./...
```

## What It Detects

| Language | Input Sources |
|----------|---------------|
| Go | `URL.Query().Get()`, `FormValue()`, `Header.Get()`, `os.Getenv()` |
| Python | `request.args`, `request.form`, `os.getenv()`, `os.environ` |
| JS/TS | `req.query`, `req.params`, `req.body`, `process.env` |

## 📊 Why Pay for BoundaryGuard?

**Every data breach starts at an input boundary.** Most teams don't know where all their input boundaries are.

- **Save 10+ hours** per security audit — automated discovery vs manual grep
- **Catch injection vectors** before attackers do — XSS, SQLi, CRLF, SSTI payloads
- **Automate** what security consultants charge $200/hr for
- **Zero dependencies** — single static binary, no runtime, no agents

## 💰 Pricing

| Feature | Free | Pro $49/mo | Enterprise $299/mo |
|---------|------|------------|--------------------|
| Languages | Go, Python, JS | + Java, Rust, C# | + Custom parsers |
| Max files/scan | 5 | Unlimited | Unlimited |
| Output formats | Text | + JSON, SARIF | + Custom formats |
| Validation rules | Basic (2/type) | OWASP Top 10 (10+) | + Custom rule packs |
| Fuzz payloads | 6/boundary | 50+/boundary | + Custom payloads |
| CI `--fail` gate | ❌ | ✅ | ✅ |
| SARIF → GitHub Security | ❌ | ✅ | ✅ |
| Trend dashboard | ❌ | ❌ | ✅ Web UI |
| SSO & audit log | ❌ | ❌ | ✅ |
| Support | Community | Email (48h) | Dedicated Slack |

## CI Integration (Pro)

```yaml
- name: BoundaryGuard
  run: boundaryguard --dir . --format json --fail
```

## License

BSL 1.1 — Free for teams ≤5 devs. Pro/Enterprise license required for larger teams.
