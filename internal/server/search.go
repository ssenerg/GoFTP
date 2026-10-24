package server

import (
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

// searchPath finds files and folders by name, in a folder and the folders
// in it, among what the visitor may read:
//
//	GET /.search/?q=WORDS[&in=DIR][&folders=1]
//
// Every word has to be part of a name, in any case. folders=1 finds
// folders only, and without words lists the folders in DIR. JSON clients
// get {"results": [{"path", "name", "dir", "size", "modified"}], "more"}.
const searchPath = "/.search/"

// A search looks through so many entries for so long at most, and stops
// at so many matches.
var (
	searchEntries = 100_000
	searchTime    = 5 * time.Second
	searchHits    = 200
	folderHits    = 20
)

type searchData struct {
	page
	Query    string
	In       string // the folder searched, as a path
	InName   string
	InHref   string
	Searched bool
	Hits     []searchHit
	Summary  string
	// Stopped says why the search ended early, if it did.
	Stopped string
}

type searchHit struct {
	listItem
	Folder, FolderHref string // where it is
}

func (s *Server) search(c fiber.Ctx) error {
	in := c.Query("in", "/")
	inPath, ok := formPath(in)
	if !ok {
		return fiber.ErrBadRequest
	}
	if hidden(inPath) {
		return fiber.ErrNotFound
	}
	// Checked before the folder is looked up, so that the answer does not
	// reveal what exists.
	if ok, err := s.allowed(c, object(inPath, true), auth.ActRead); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}
	allow := s.visitorRules(c)
	f, info, realPath, err := s.lookup(inPath, allow)
	if err != nil {
		return err
	}
	_ = f.Close()
	if !info.IsDir() {
		return fiber.ErrNotFound
	}

	query := strings.TrimSpace(c.Query("q"))
	words := strings.Fields(strings.ToLower(query))
	foldersOnly := c.Query("folders") == "1"
	limit := searchHits
	if foldersOnly {
		limit = folderHits
	}
	var (
		hits    []listItem
		stopped string
	)
	if len(words) > 0 || foldersOnly {
		hits, stopped = s.find(inPath, realPath, words, foldersOnly, limit, allow)
	}

	c.Set(fiber.HeaderCacheControl, "no-store")
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		type result struct {
			Path     string `json:"path"`
			Name     string `json:"name"`
			Dir      bool   `json:"dir"`
			Size     int64  `json:"size"`
			Modified string `json:"modified"`
		}
		results := make([]result, 0, len(hits))
		for _, it := range hits {
			results = append(results, result{Path: object(it.Path, it.IsDir), Name: it.Name, Dir: it.IsDir, Size: it.size, Modified: it.ModISO})
		}
		return c.JSON(fiber.Map{"results": results, "more": stopped != ""})
	}

	data := searchData{page: s.page(c, "Search"), Query: query, In: inPath, InName: shareName(inPath),
		InHref: escapePath(object(inPath, true)), Searched: len(words) > 0}
	if inHome(s.homeOf(userOf(c)), inPath) == "/" {
		data.InName = "My files"
	}
	if query != "" {
		data.Title = query + " · Search"
	}
	for _, it := range hits {
		folder := path.Dir(it.Path)
		data.Hits = append(data.Hits, searchHit{listItem: it, Folder: folder, FolderHref: escapePath(object(folder, true))})
	}
	data.Summary = matchCount(len(hits))
	switch stopped {
	case "more":
		data.Stopped = "Only the first " + matchCount(limit) + " are shown. Add words to narrow the search."
	case "slow":
		data.Stopped = "The search stopped before looking everywhere: there is a lot here. Search in a folder further down, or add words."
	}
	return s.render(c, fiber.StatusOK, "search", data)
}

// find looks for entries whose names hold all words in the folder at
// urlPath (really at realPath) and the folders in it, folders nearer the
// top first, among what allow lets the visitor read; with foldersOnly,
// for folders only, and without words just the folders in it. It stops at
// limit matches ("more") or after looking long ("slow"). Folders that
// symlinks lead to are searched once.
func (s *Server) find(urlPath, realPath string, words []string, foldersOnly bool, limit int, allow allowFunc) ([]listItem, string) {
	deadline := time.Now().Add(searchTime)
	queue := []listItem{{Path: urlPath, real: realPath}}
	seen := map[string]bool{realPath: true}
	scanned := 0
	var hits []listItem
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		items, err := s.readable(dir.Path, dir.real, allow)
		if err != nil {
			continue
		}
		for _, it := range items {
			scanned++
			if (it.IsDir || !foldersOnly) && matches(it.Key, words) {
				if len(hits) == limit {
					return hits, "more"
				}
				hits = append(hits, it)
			}
			if it.IsDir && len(words) > 0 && !seen[it.real] {
				seen[it.real] = true
				queue = append(queue, it)
			}
		}
		if len(queue) > 0 && (scanned >= searchEntries || time.Now().After(deadline)) {
			return hits, "slow"
		}
	}
	return hits, ""
}

// matchCount says how many matches there are, e.g. "3 matches".
func matchCount(n int) string {
	switch n {
	case 0:
		return "No matches"
	case 1:
		return "1 match"
	}
	return strconv.Itoa(n) + " matches"
}

// matches reports whether key holds all words.
func matches(key string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(key, w) {
			return false
		}
	}
	return true
}
