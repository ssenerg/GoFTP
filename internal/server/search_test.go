package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"goftp/internal/auth"
)

func TestSearch(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/Tax Return 2024.pdf", "t")
	f.write(t, "docs/2023/tax-2023.pdf", "t")
	f.write(t, "docs/.secret-tax", "s")
	f.write(t, "photos/beach.jpg", "b")
	f.write(t, "hr/tax.txt", "h")
	f.write(t, "busy-tax.iso", "half")
	f.write(t, lockName("busy-tax.iso"), "another tool's lock")
	for _, rule := range [][3]string{{"user", "!/hr/*", "*"}, {"admin", "/hr/*", auth.ActRead}} {
		if _, err := ta.svc.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink back to the top is followed once, not forever.
	if err := os.Symlink("..", filepath.Join(f.dir, "docs", "loop")); err != nil {
		t.Skip(err)
	}
	user := f.as("user")
	hits := func(body string) []string {
		var names []string
		for _, m := range regexp.MustCompile(`<td class="name"><a href="([^"]+)"`).FindAllStringSubmatch(body, -1) {
			names = append(names, m[1])
		}
		return names
	}

	for query, want := range map[string]string{
		"q=tax":               "/docs/Tax%20Return%202024.pdf?view /docs/2023/tax-2023.pdf?view",
		"q=TAX+2024":          "/docs/Tax%20Return%202024.pdf?view",
		"q=tax&in=/docs/2023": "/docs/2023/tax-2023.pdf?view",
		"q=tax&in=%2Fdocs%2F": "/docs/Tax%20Return%202024.pdf?view /docs/2023/tax-2023.pdf?view",
		"q=beach":             "/photos/beach.jpg?view",
		"q=2023":              "/docs/2023/ /docs/2023/tax-2023.pdf?view",
		"q=nothing+like+this": "",
		"q=":                  "",
		"q=photos&in=/docs/":  "/docs/loop/photos/",
		"q=loop":              "/docs/loop/",
	} {
		resp, body := user.do(t, "GET", searchPath+"?"+query, "Accept", "text/html")
		expectStatus(t, resp, http.StatusOK)
		if got := strings.Join(hits(body), " "); got != want {
			t.Errorf("?%s: found %q, want %q", query, got, want)
		}
	}
	_, body := user.do(t, "GET", searchPath+"?q=tax", "Accept", "text/html")
	for _, want := range []string{`2 matches in <a href="/">All files</a>`, `value="tax"`, `<td class="where-col"><a href="/docs/2023/">/docs/2023</a></td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("results lack %s", want)
		}
	}
	_, body = user.do(t, "GET", searchPath+"?q=tax&in=/docs", "Accept", "text/html")
	if !strings.Contains(body, `<input type="hidden" name="in" value="/docs">`) || !strings.Contains(body, `<a href="/.search/?q=tax">Search all files</a>`) {
		t.Error("a search in a folder does not offer to search everywhere")
	}
	if _, body := f.as("admin").do(t, "GET", searchPath+"?q=tax", "Accept", "text/html"); !strings.Contains(strings.Join(hits(body), " "), "/hr/tax.txt") {
		t.Error("the admin does not find /hr/tax.txt")
	}

	// Folders, for fields that ask for one.
	var found struct {
		Results []struct {
			Path string `json:"path"`
			Dir  bool   `json:"dir"`
		} `json:"results"`
		More bool `json:"more"`
	}
	decode := func(body string) string {
		t.Helper()
		found.Results = nil
		if err := json.Unmarshal([]byte(body), &found); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		var paths []string
		for _, r := range found.Results {
			paths = append(paths, r.Path)
		}
		return strings.Join(paths, " ")
	}
	for query, want := range map[string]string{
		"folders=1":                "/docs/ /photos/",
		"folders=1&in=/docs/":      "/docs/2023/ /docs/loop/",
		"folders=1&q=20":           "/docs/2023/",
		"q=beach":                  "/photos/beach.jpg",
		"folders=1&q=beach":        "",
		"folders=1&in=/docs/2023/": "",
	} {
		resp, body := user.do(t, "GET", searchPath+"?"+query, "Accept", "application/json")
		expectStatus(t, resp, http.StatusOK)
		if got := decode(body); got != want {
			t.Errorf("?%s: %q, want %q", query, got, want)
		}
	}

	// Many matches are cut short.
	defer func(n int) { searchHits = n }(searchHits)
	searchHits = 1
	_, body = user.do(t, "GET", searchPath+"?q=tax", "Accept", "application/json")
	if decode(body) != "/docs/Tax%20Return%202024.pdf" && !found.More {
		t.Errorf("cut short: %s", body)
	}
	if _, body := user.do(t, "GET", searchPath+"?q=tax", "Accept", "text/html"); !strings.Contains(body, "Only the first 1 match are shown.") {
		t.Error("not told the search was cut short")
	}

	for query, want := range map[string]int{
		"q=tax&in=/hr":               403,
		"q=tax&in=/nope":             404,
		"q=tax&in=/.git":             404,
		"q=tax&in=/photos/beach.jpg": 404,
		"q=tax&in=docs":              400,
	} {
		if resp, _ := user.do(t, "GET", searchPath+"?"+query); resp.StatusCode != want {
			t.Errorf("?%s: %d, want %d", query, resp.StatusCode, want)
		}
	}
	if resp, _ := f.as("").do(t, "GET", searchPath+"?q=tax"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", resp.StatusCode)
	}

	// Folder pages search from their filter.
	_, body = user.do(t, "GET", "/docs/")
	if !strings.Contains(body, `<form id="search" class="search-form" method="get" action="/.search/" role="search">`) ||
		!strings.Contains(body, `<input type="hidden" name="in" value="/docs">`) {
		t.Error("the folder's filter does not search")
	}
}
