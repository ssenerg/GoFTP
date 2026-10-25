package auth

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// FolderShare lets a user into a folder of another user's home: to read
// what is in it, or with Write to change it too, but for deleting or
// renaming the folder itself. It lets them do only what its owner may do
// there and share, and the rules of administrators for the same paths come
// first. It ends at ExpiresAt, if set, or when the folder is deleted or
// leaves the home, and follows it when it moves within the home (see
// MoveFolderShares).
type FolderShare struct {
	ID        int64
	OwnerID   int64
	Owner     string // the owner's username
	Path      string // URL path where the folder really is
	UserID    int64  // who it is shared with
	User      string // their username
	Write     bool
	CreatedAt time.Time
	ExpiresAt time.Time // zero for never
}

// MaxFolderShares bounds the folder shares of one owner.
const MaxFolderShares = 200

// ShareFolder shares the folder at path, which really is owner's home or in
// it, with the user username (ErrNotFound if there is none), to read or with
// write to change, for ttl or with 0 until it is stopped; sharing it with
// them again changes how and for how long. It does not check that the
// folder exists.
func (s *Service) ShareFolder(ctx context.Context, owner *User, path, username string, write bool, ttl time.Duration) (*FolderShare, error) {
	home := s.HomeOf(owner.Username)
	if home == "" || !s.within(path, home) {
		return nil, fmt.Errorf("%w: only folders in your home can be shared with people", ErrInvalid)
	}
	user, err := s.store.UserByName(ctx, NormalizeUsername(username))
	if err != nil {
		return nil, err
	}
	if user.ID == owner.ID {
		return nil, fmt.Errorf("%w: it is yours already", ErrInvalid)
	}
	if s.folder() != nil {
		// The folder spelled otherwise is the same folder.
		shares, err := s.store.FolderShares(ctx, owner.ID)
		if err != nil {
			return nil, err
		}
		for _, fs := range shares {
			if fs.UserID == user.ID && s.within(fs.Path, path) && s.within(path, fs.Path) {
				path = fs.Path
			}
		}
	}
	fs := &FolderShare{OwnerID: owner.ID, Owner: owner.Username, Path: path, UserID: user.ID, User: user.Username, Write: write}
	if ttl > 0 {
		fs.ExpiresAt = time.Now().Add(ttl)
	}
	if err := s.store.ShareFolder(ctx, fs); err != nil {
		return nil, err
	}
	return fs, nil
}

// FolderShares lists the folders owner shares with people that have not
// expired, newest first; those of everyone with all.
func (s *Service) FolderShares(ctx context.Context, owner *User, all bool) ([]FolderShare, error) {
	if all {
		return s.store.FolderShares(ctx, 0)
	}
	return s.store.FolderShares(ctx, owner.ID)
}

// SharedWith lists the folders shared with u that are still in the homes
// of their owners, by path.
func (s *Service) SharedWith(ctx context.Context, u *User) ([]FolderShare, error) {
	if s.Homes() == "" {
		return nil, nil
	}
	shares, err := s.store.SharedWith(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	// Homes may have moved since, to where the paths mean something else.
	out := shares[:0]
	for _, fs := range shares {
		if s.within(fs.Path, s.HomeOf(fs.Owner)) {
			out = append(out, fs)
		}
	}
	return out, nil
}

// UnshareFolder ends the folder share id, of which u is the owner or the
// user it is shared with, unless all is set, and returns it (ErrNotFound
// if there is no such share).
func (s *Service) UnshareFolder(ctx context.Context, u *User, id int64, all bool) (*FolderShare, error) {
	by := u.ID
	if all {
		by = 0
	}
	return s.store.DeleteFolderShare(ctx, id, by)
}

// MoveFolderShares has the shares of the folder at the URL path from, and of
// those in it, follow it to to, where it moved; they end with to "", as it
// was deleted, or when it left its home. Shares left at to by a folder
// that is gone end as well: they must not reach what takes its place.
func (s *Service) MoveFolderShares(ctx context.Context, from, to string) error {
	if s.Homes() == "" {
		return nil
	}
	var shares []FolderShare
	homes := map[int64]string{}
	for _, p := range []string{from, to} {
		owner, err := s.homeOwner(ctx, p)
		if err != nil {
			return err
		}
		if owner == nil || homes[owner.ID] != "" {
			continue
		}
		homes[owner.ID] = s.HomeOf(owner.Username)
		more, err := s.store.FolderShares(ctx, owner.ID)
		if err != nil {
			return err
		}
		shares = append(shares, more...)
	}
	for _, fs := range shares {
		var err error
		switch {
		case s.within(fs.Path, from) && to != "" && s.within(to, homes[fs.OwnerID]):
			err = s.store.MoveFolderShare(ctx, fs.ID, to+below(fs.Path, from))
		case s.within(fs.Path, from), to != "" && s.within(fs.Path, to):
			_, err = s.store.DeleteFolderShare(ctx, fs.ID, 0)
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// homeOwner returns the user whose home the URL path p is in, or is; nil if
// it is in none.
func (s *Service) homeOwner(ctx context.Context, p string) (*User, error) {
	rest, ok := strings.CutPrefix(p, s.Homes()+"/")
	name, _, _ := strings.Cut(rest, "/")
	if !ok || name == "" {
		return nil, nil
	}
	u, err := s.store.UserByName(ctx, NormalizeUsername(name))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return u, err
}

// within reports whether the URL path p is the folder dir or inside it,
// as rules compare paths.
func (s *Service) within(p, dir string) bool {
	if path.Clean(p) != p {
		return false
	}
	if fold := s.folder(); fold != nil {
		p, dir = fold(p), fold(dir)
	}
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// below returns what follows the folder dir in the URL path p, which is in
// it: "" for dir itself, or e.g. "/a/b".
func below(p, dir string) string {
	if rest := strings.Split(p, "/")[strings.Count(dir, "/")+1:]; len(rest) > 0 {
		return "/" + strings.Join(rest, "/")
	}
	return ""
}

// shareRules are the rules of the folder shared with someone by fs, whose
// owner has the rules owner: built in, so that administrators' rules for
// the same paths come first.
func shareRules(fs FolderShare, owner *Rules) []rule {
	base := fs.Path + "/"
	rules := []rule{{base: base, wildcard: true, act: ActRead, distance: builtIn, owner: owner}}
	if fs.Write {
		for _, act := range []string{ActWrite, ActOverwrite, ActDelete} {
			rules = append(rules, rule{base: base, wildcard: true, act: act, distance: builtIn, owner: owner})
		}
		// The folder itself stays, whatever happens in it.
		rules = append(rules, rule{base: base, deny: true, act: ActDelete, distance: builtIn})
	}
	return rules
}
