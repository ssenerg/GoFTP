package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGallery(t *testing.T) {
	f := newFixture(t)
	html := []string{"Accept", "text/html"}
	// Pictures named against the order they were taken in.
	for i, name := range []string{"c.jpg", "b.png", "a.jpg"} {
		f.write(t, "photos/"+name, "not really a picture")
		mod := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(filepath.Join(f.dir, "photos", name), mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	f.write(t, "photos/notes.txt", "notes")
	f.write(t, "docs/a.txt", "a")
	f.write(t, "docs/b.pdf", "b")
	f.write(t, "docs/c.jpg", "c")

	// Folders of mostly pictures and videos are a grid, others a list.
	_, body := f.do(t, "GET", "/photos/", html...)
	if !strings.Contains(body, `<table class="files grid" id="entries" data-layout="grid" data-auto>`) ||
		!strings.Contains(body, `<a class="btn" href="?layout=grid" data-layout="grid" title="Grid" aria-label="Grid" aria-current="true">`) {
		t.Errorf("photos: %s", body)
	}
	_, body = f.do(t, "GET", "/docs/", html...)
	if !strings.Contains(body, `<table class="files" id="entries" data-layout="list" data-auto>`) {
		t.Errorf("docs: %s", body)
	}
	// As asked, and kept when sorting.
	_, body = f.do(t, "GET", "/photos/?layout=list&sort=modified", html...)
	if !strings.Contains(body, `<table class="files" id="entries" data-layout="list">`) ||
		!strings.Contains(body, `href="?sort=modified&amp;order=desc&amp;layout=list"`) ||
		!strings.Contains(body, `href="?layout=grid&amp;sort=modified"`) {
		t.Errorf("asked for a list: %s", body)
	}
	// The viewer goes through the folder in the order it was listed in.
	_, body = f.do(t, "GET", "/photos/?sort=modified&order=desc", html...)
	if !strings.Contains(body, `href="/photos/a.jpg?view&amp;sort=modified&amp;order=desc"`) {
		t.Errorf("viewer links: %s", body)
	}
	_, body = f.do(t, "GET", "/photos/b.png?view&sort=modified&order=desc", html...)
	for _, want := range []string{
		`id="prev" href="/photos/a.jpg?view&amp;sort=modified&amp;order=desc"`,
		`id="next" href="/photos/c.jpg?view&amp;sort=modified&amp;order=desc"`,
		`<link rel="prefetch" href="/photos/c.jpg?inline" as="image">`,
		`data-folder="/photos/?sort=modified&amp;order=desc"`,
		"2 of 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer lacks %s", want)
		}
	}
	_, body = f.do(t, "GET", "/photos/b.png?view", html...)
	if !strings.Contains(body, `id="prev" href="/photos/a.jpg?view"`) || !strings.Contains(body, `data-folder="/photos/"`) {
		t.Errorf("by name: %s", body)
	}
}
