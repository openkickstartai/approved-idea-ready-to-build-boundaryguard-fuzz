package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Report struct {
	TotalFiles  int        `json:"total_files"`
	TotalBounds int        `json:"total_boundaries"`
	Boundaries  []Boundary `json:"boundaries"`
}

func main() {
	dir := flag.String("dir", ".", "Directory to scan")
	format := flag.String("format", "text", "Output: text or json")
	maxFiles := flag.Int("max-files", 0, "File limit (0=unlimited, free=5)")
	failFlag := flag.Bool("fail", false, "Exit 1 if boundaries found")
	flag.Parse()

	var all []Boundary
	n := 0
	filepath.Walk(*dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".go" && ext != ".py" && ext != ".js" && ext != ".ts" {
			return nil
		}
		if *maxFiles > 0 && n >= *maxFiles {
			return nil
		}
		n++
		all = append(all, ScanFile(p, ext)...)
		return nil
	})

	rpt := Report{TotalFiles: n, TotalBounds: len(all), Boundaries: all}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rpt)
	} else {
		fmt.Println("\U0001f6e1\ufe0f  BoundaryGuard Report")
		fmt.Printf("   Files scanned: %d | Boundaries found: %d\n\n", rpt.TotalFiles, rpt.TotalBounds)
		for i, b := range all {
			fmt.Printf("[%d] %s:%d\n", i+1, b.File, b.Line)
			fmt.Printf("    Type: %s | Source: %s | Var: %s\n", b.Type, b.Source, b.Variable)
			fmt.Printf("    Rules: %s\n", strings.Join(b.Validation, "; "))
			fmt.Printf("    Fuzz:  %s\n\n", strings.Join(b.FuzzInputs, ", "))
		}
		if rpt.TotalBounds == 0 {
			fmt.Println("   No unguarded boundaries found. Clean!")
		}
	}

	if *failFlag && len(all) > 0 {
		os.Exit(1)
	}
}
