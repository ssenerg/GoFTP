package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// AppPassword lets an app, such as a sync app, sign in as its user over
// WebDAV, with a password of its own that can be revoked alone.
type AppPassword struct {
	ID         int64
	UserID     int64
	Name       string // what it is for, e.g. "rclone on my laptop"
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never
}

// MaxAppPasswords bounds the app passwords of one user.
const MaxAppPasswords = 20

// maxAppPasswordName bounds the length of an app password's name.
const maxAppPasswordName = 64

// appPasswordLength is the number of letters and digits of an app password,
// 120 bits of it; it is shown in groups of four, which may be left out.
const appPasswordLength = 24

// CreateAppPassword makes an app password named name for u, after checking
// their password, and returns it: it is not kept, so it can only be shown
// now. The password keeps a stolen session from becoming an app password,
// which would outlive it.
func (s *Service) CreateAppPassword(ctx context.Context, u *User, name, password string) (string, *AppPassword, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxAppPasswordName || strings.ContainsFunc(name, unicode.IsControl) {
		return "", nil, fmt.Errorf("%w: name it in up to %d characters", ErrInvalid, maxAppPasswordName)
	}
	if err := s.checkPasswordOf(ctx, u, password); err != nil {
		return "", nil, err
	}
	raw := strings.ToLower(rand.Text()[:appPasswordLength])
	var groups []string
	for i := 0; i < len(raw); i += 4 {
		groups = append(groups, raw[i:i+4])
	}
	ap := &AppPassword{UserID: u.ID, Name: name}
	err := s.store.CreateAppPassword(ctx, tokenHash(raw), ap, u.PasswordHash)
	if errors.Is(err, ErrNotFound) {
		// The password changed meanwhile, ending what it made.
		return "", nil, errChangedMeanwhile
	}
	if err != nil {
		return "", nil, err
	}
	return strings.Join(groups, "-"), ap, nil
}

// AppPasswords lists u's app passwords, newest first.
func (s *Service) AppPasswords(ctx context.Context, u *User) ([]AppPassword, error) {
	return s.store.AppPasswords(ctx, u.ID)
}

// RevokeAppPassword ends u's app password id (ErrNotFound if u has none
// of that ID).
func (s *Service) RevokeAppPassword(ctx context.Context, u *User, id int64) error {
	return s.store.DeleteAppPassword(ctx, u.ID, id)
}

// AppPasswordUser returns the user username, if password is one of their
// app passwords (ErrNotFound otherwise). Case and the dashes between groups
// do not matter.
func (s *Service) AppPasswordUser(ctx context.Context, username, password string) (*User, error) {
	raw := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(password), "-", ""))
	if len(raw) != appPasswordLength {
		return nil, ErrNotFound
	}
	for _, c := range raw {
		if !('a' <= c && c <= 'z' || '2' <= c && c <= '7') {
			return nil, ErrNotFound
		}
	}
	return s.store.AppPasswordUser(ctx, NormalizeUsername(username), tokenHash(raw))
}
