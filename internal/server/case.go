package server

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// checkNames finds out how the file system of the served folder finds
// names, and returns how rules have to compare paths there (see
// auth.Service.SetFold): nil, as they are, where names are found only as
// spelled. Where the same name in other case or Unicode normalization is
// found too, /HOME/bob would get past the rules for /home/bob, so rules
// compare folded paths. That is only safe where the kernel also tells how
// names are stored (see fdPath), as other aliases may exist, such as the
// short names of FAT and NTFS: such folders are refused.
func (s *Server) checkNames() (func(string) string, error) {
	var caseless, normless bool
	probe := tempPrefix + "names-é-" + strings.ToLower(rand.Text()) + tempSuffix
	if f, err := s.root.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		_ = f.Close()
		defer s.root.Remove(probe)
		if caseless = s.sameEntry(probe, swapCase(probe)); caseless && !s.storedSpelling(swapCase(probe), probe) {
			return nil, s.namesError()
		}
		if normless = s.sameEntry(probe, norm.NFD.String(probe)); normless && !s.storedSpelling(norm.NFD.String(probe), probe) {
			return nil, s.namesError()
		}
	} else if caseless, normless, err = s.judgeNames(); err != nil {
		return nil, err
	}
	switch {
	case caseless && normless:
		return func(p string) string { return strings.ToLower(norm.NFC.String(p)) }, nil
	case caseless:
		return strings.ToLower, nil
	case normless:
		return norm.NFC.String, nil
	}
	return nil, nil
}

// judgeNames is checkNames for a folder goftp may not write to, judged by
// what is in it.
func (s *Server) judgeNames() (caseless, normless bool, err error) {
	d, err := s.root.Open(".")
	if err != nil {
		return false, false, err
	}
	names, _ := d.Readdirnames(1000)
	_ = d.Close()
	caseChecked, normChecked := false, false
	for _, name := range names {
		if other := swapCase(name); !caseChecked && other != name {
			caseChecked = true
			if caseless = s.sameEntry(name, other); caseless && !s.storedSpelling(other, name) {
				return false, false, s.namesError()
			}
		}
		if other := norm.NFD.String(name); !normChecked && other != name {
			normChecked = true
			if normless = s.sameEntry(name, other); normless && !s.storedSpelling(other, name) {
				return false, false, s.namesError()
			}
		}
	}
	return caseless, normless, nil
}

// sameEntry reports whether the names a and b of the root find the same
// entry.
func (s *Server) sameEntry(a, b string) bool {
	ia, err := s.root.Lstat(a)
	if err != nil {
		return false
	}
	ib, err := s.root.Lstat(b)
	return err == nil && os.SameFile(ia, ib)
}

// storedSpelling reports whether opening the entry name of the root tells
// that it is stored as stored.
func (s *Server) storedSpelling(name, stored string) bool {
	f, err := s.root.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	p, ok := fdPath(f)
	return ok && filepath.Base(p) == stored
}

func (s *Server) namesError() error {
	return fmt.Errorf("%s is on a file system that finds names in other spellings too, where rules could be got around: "+
		"serve a folder on one that does not", s.rootPath)
}

// swapCase turns the upper case letters of name to lower case and the
// lower case ones to upper case.
func swapCase(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsUpper(r):
			return unicode.ToLower(r)
		case unicode.IsLower(r):
			return unicode.ToUpper(r)
		}
		return r
	}, name)
}
