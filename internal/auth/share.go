package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxShares bounds the unexpired links one user may have.
	MaxShares = 1000
	// MinSharePasswordLength is the shortest password a link may have.
	MinSharePasswordLength = 8
)

// CreateShare creates a link to the file or folder at path for u, which
// works for ttl, and returns its token. With a password, visitors need it
// too.
func (s *Service) CreateShare(ctx context.Context, u *User, path string, isDir bool, ttl time.Duration, password string) (string, *Share, error) {
	sh := &Share{Path: path, IsDir: isDir, CreatedBy: u.ID, Creator: u.Username, ExpiresAt: time.Now().Add(ttl)}
	if password != "" {
		switch {
		case utf8.RuneCountInString(password) < MinSharePasswordLength:
			return "", nil, fmt.Errorf("%w: use at least %d characters", ErrWeakPassword, MinSharePasswordLength)
		case len(password) > MaxPasswordLength:
			return "", nil, fmt.Errorf("%w: use at most %d bytes", ErrWeakPassword, MaxPasswordLength)
		}
		hash, err := s.hash(ctx, password)
		if err != nil {
			return "", nil, err
		}
		sh.PasswordHash = hash
	}
	token := newToken()
	if err := s.store.CreateShare(ctx, tokenHash(token), sh); err != nil {
		return "", nil, err
	}
	return token, sh, nil
}

// ShareByToken returns the link with token, unless it expired or was
// revoked (ErrNotFound).
func (s *Service) ShareByToken(ctx context.Context, token string) (*Share, error) {
	if !ValidToken(token) {
		return nil, ErrNotFound
	}
	return s.store.ShareByToken(ctx, tokenHash(token))
}

// ValidToken reports whether token could be a session or link token.
func ValidToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	for _, c := range []byte(token) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// CheckSharePassword reports whether password opens sh.
func (s *Service) CheckSharePassword(ctx context.Context, sh *Share, password string) (bool, error) {
	if sh.PasswordHash == "" {
		return true, nil
	}
	if password == "" || len(password) > MaxPasswordLength {
		return false, nil
	}
	release, err := s.acquireHashing(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	return verifyPassword(sh.PasswordHash, password), nil
}

// UnlockShare returns proof that a visitor gave the password of the link
// with token, for a cookie. It works until until.
func UnlockShare(sh *Share, token string, until time.Time) string {
	exp := strconv.FormatInt(until.Unix(), 10)
	return exp + "." + base64.RawURLEncoding.EncodeToString(unlockMAC(sh, token, exp))
}

// ShareUnlocked reports whether proof, from UnlockShare, still opens sh.
// Links without a password have nothing to unlock, and anyone could make
// proofs for them.
func ShareUnlocked(sh *Share, token, proof string, now time.Time) bool {
	exp, mac, ok := strings.Cut(proof, ".")
	if !ok || sh.PasswordHash == "" {
		return false
	}
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || !now.Before(time.Unix(unix, 0)) {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(mac)
	return err == nil && hmac.Equal(got, unlockMAC(sh, token, exp))
}

// unlockMAC is keyed with the hash of the link's password, which only the
// server knows.
func unlockMAC(sh *Share, token, exp string) []byte {
	m := hmac.New(sha256.New, []byte(sh.PasswordHash))
	m.Write([]byte("goftp share unlock\x00" + token + "\x00" + exp))
	return m.Sum(nil)
}

// Shares lists the unexpired links u created, or everyone's if all is set.
func (s *Service) Shares(ctx context.Context, u *User, all bool) ([]Share, error) {
	if all {
		return s.store.Shares(ctx, 0)
	}
	return s.store.Shares(ctx, u.ID)
}

// RevokeShare deletes the link id if u created it, or whoever did if all
// is set.
func (s *Service) RevokeShare(ctx context.Context, u *User, id int64, all bool) error {
	if all {
		return s.store.DeleteShare(ctx, id, 0)
	}
	return s.store.DeleteShare(ctx, id, u.ID)
}

// MayShare reports whether username may create links anywhere at all.
func (s *Service) MayShare(username string) bool { return s.mayAnywhere(username, ActShare) }

// MayDelete reports whether username may delete anything anywhere.
func (s *Service) MayDelete(username string) bool { return s.mayAnywhere(username, ActDelete) }

// MayWrite reports whether username may add files anywhere at all.
func (s *Service) MayWrite(username string) bool { return s.mayAnywhere(username, ActWrite) }

// mayAnywhere reports whether some rule, not a denial, lets username
// perform act.
func (s *Service) mayAnywhere(username, act string) bool {
	for _, sub := range []string{Subject(username), Anonymous} {
		perms, err := s.enforcer.GetImplicitPermissionsForUser(sub)
		if err != nil {
			continue
		}
		for _, p := range perms {
			if len(p) > 2 && !strings.HasPrefix(p[1], "!") && (p[2] == act || p[2] == "*") {
				return true
			}
		}
	}
	return false
}
