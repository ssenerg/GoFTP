// Package authtest provides an in-memory auth.Store for tests.
package authtest

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"goftp/internal/auth"
)

type Store struct {
	mu       sync.Mutex
	nextID   int64
	users    map[int64]*auth.User
	sessions map[string]session
	shares   map[string]*auth.Share // by token hash
	uploads  map[string]*upload     // by token hash
}

type upload struct {
	auth.Upload
	writer      string
	writerUntil time.Time
}

type session struct {
	userID  int64
	expires time.Time
}

var _ auth.Store = (*Store)(nil)

func NewStore() *Store {
	return &Store{users: make(map[int64]*auth.User), sessions: make(map[string]session), shares: make(map[string]*auth.Share),
		uploads: make(map[string]*upload)}
}

// NewService returns a service with an empty store and the default policy.
func NewService(ttl time.Duration) (*auth.Service, *Store) {
	e, err := auth.NewEnforcer(nil)
	if err != nil {
		panic(err)
	}
	st := NewStore()
	return auth.NewService(st, e, ttl), st
}

// Sessions returns the number of stored sessions.
func (s *Store) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Store) CreateUser(_ context.Context, username, passwordHash string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			return 0, auth.ErrExists
		}
	}
	s.nextID++
	s.users[s.nextID] = &auth.User{ID: s.nextID, Username: username, PasswordHash: passwordHash,
		MustChangePassword: true, CreatedAt: time.Now()}
	return s.nextID, nil
}

func (s *Store) UserByName(_ context.Context, username string) (*auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			c := *u
			return &c, nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *Store) ListUsers(context.Context) ([]auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auth.User
	for _, u := range s.users {
		out = append(out, *u)
	}
	slices.SortFunc(out, func(a, b auth.User) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
}

func (s *Store) SetPassword(_ context.Context, userID int64, passwordHash string, mustChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrNotFound
	}
	u.PasswordHash, u.MustChangePassword = passwordHash, mustChange
	s.deleteSessions(userID)
	if mustChange {
		s.deleteShares(userID)
	}
	return nil
}

func (s *Store) DeleteUser(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return auth.ErrNotFound
	}
	delete(s.users, userID)
	s.deleteSessions(userID)
	s.deleteShares(userID)
	return nil
}

func (s *Store) CreateSession(_ context.Context, tokenHash []byte, u *auth.User, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.users[u.ID]; !ok || cur.PasswordHash != u.PasswordHash {
		return auth.ErrNotFound
	}
	s.sessions[string(tokenHash)] = session{userID: u.ID, expires: expires}
	return nil
}

func (s *Store) SessionUser(_ context.Context, tokenHash []byte) (*auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[string(tokenHash)]
	if !ok || !time.Now().Before(v.expires) {
		return nil, auth.ErrNotFound
	}
	c := *s.users[v.userID]
	return &c, nil
}

func (s *Store) DeleteSession(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, string(tokenHash))
	return nil
}

func (s *Store) deleteSessions(userID int64) {
	for k, v := range s.sessions {
		if v.userID == userID {
			delete(s.sessions, k)
		}
	}
}

func (s *Store) DeleteExpiredSessions(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if !time.Now().Before(v.expires) {
			delete(s.sessions, k)
		}
	}
	return nil
}

func (s *Store) CreateShare(_ context.Context, tokenHash []byte, sh *auth.Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[sh.CreatedBy]; !ok {
		return auth.ErrNotFound
	}
	n := 0
	for _, v := range s.shares {
		if v.CreatedBy == sh.CreatedBy && time.Now().Before(v.ExpiresAt) {
			n++
		}
	}
	if n >= auth.MaxShares {
		return auth.ErrTooMany
	}
	s.nextID++
	sh.ID, sh.CreatedAt = s.nextID, time.Now()
	c := *sh
	s.shares[string(tokenHash)] = &c
	return nil
}

func (s *Store) ShareByToken(_ context.Context, tokenHash []byte) (*auth.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shares[string(tokenHash)]
	if !ok || !time.Now().Before(sh.ExpiresAt) {
		return nil, auth.ErrNotFound
	}
	c := *sh
	c.Creator = s.users[sh.CreatedBy].Username
	return &c, nil
}

func (s *Store) ShareByID(_ context.Context, id int64) (*auth.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sh := range s.shares {
		if sh.ID == id && time.Now().Before(sh.ExpiresAt) {
			c := *sh
			c.Creator = s.users[sh.CreatedBy].Username
			return &c, nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *Store) UseShare(_ context.Context, id int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sh := range s.shares {
		if sh.ID == id && time.Now().Before(sh.ExpiresAt) && !sh.UsedUp() {
			sh.Uses++
			sh.LastUsedAt = time.Now()
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) TouchShare(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sh := range s.shares {
		if sh.ID == id {
			sh.LastUsedAt = time.Now()
		}
	}
	return nil
}

func (s *Store) Shares(_ context.Context, userID int64) ([]auth.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auth.Share
	for _, sh := range s.shares {
		if time.Now().Before(sh.ExpiresAt) && (userID == 0 || sh.CreatedBy == userID) {
			c := *sh
			c.Creator = s.users[sh.CreatedBy].Username
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b auth.Share) int { return cmp.Compare(b.ID, a.ID) })
	return out, nil
}

func (s *Store) DeleteShare(_ context.Context, id, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sh := range s.shares {
		if sh.ID == id && (userID == 0 || sh.CreatedBy == userID) {
			delete(s.shares, k)
			return nil
		}
	}
	return auth.ErrNotFound
}

func (s *Store) deleteShares(userID int64) {
	for k, sh := range s.shares {
		if sh.CreatedBy == userID {
			delete(s.shares, k)
		}
	}
}

func (s *Store) DeleteExpiredShares(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sh := range s.shares {
		if !time.Now().Before(sh.ExpiresAt) {
			delete(s.shares, k)
		}
	}
	return nil
}

func (s *Store) CreateUpload(_ context.Context, tokenHash []byte, up *auth.Upload, keep time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	now := time.Now()
	up.ID, up.CreatedAt, up.ExpiresAt = s.nextID, now, now.Add(keep)
	s.uploads[string(tokenHash)] = &upload{Upload: *up}
	return nil
}

func (s *Store) UploadByToken(_ context.Context, tokenHash []byte) (*auth.Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.uploads[string(tokenHash)]
	if !ok || !time.Now().Before(up.ExpiresAt) {
		return nil, auth.ErrNotFound
	}
	c := up.Upload
	return &c, nil
}

func (s *Store) uploadByID(id int64) *upload {
	for _, up := range s.uploads {
		if up.ID == id {
			return up
		}
	}
	return nil
}

func (s *Store) ClaimUpload(_ context.Context, id int64, writer string, lease time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	up := s.uploadByID(id)
	if up == nil || !now.Before(up.ExpiresAt) || (up.writer != "" && now.Before(up.writerUntil)) {
		return false, nil
	}
	up.writer, up.writerUntil = writer, now.Add(lease)
	return true, nil
}

func (s *Store) ExtendUpload(_ context.Context, id int64, writer string, lease, keep time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up := s.uploadByID(id)
	if up == nil || up.writer != writer {
		return false, nil
	}
	now := time.Now()
	up.writerUntil, up.ExpiresAt = now.Add(lease), now.Add(keep)
	return true, nil
}

func (s *Store) ReleaseUpload(_ context.Context, id int64, writer string, keep time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up := s.uploadByID(id); up != nil && up.writer == writer {
		up.writer, up.writerUntil, up.ExpiresAt = "", time.Time{}, time.Now().Add(keep)
	}
	return nil
}

func (s *Store) DeleteUpload(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, up := range s.uploads {
		if up.ID == id {
			delete(s.uploads, k)
		}
	}
	return nil
}

func (s *Store) TakeExpiredUploads(_ context.Context, limit int) ([]auth.Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []auth.Upload
	for k, up := range s.uploads {
		if len(out) < limit && !now.Before(up.ExpiresAt) && !now.Before(up.writerUntil) {
			out = append(out, up.Upload)
			delete(s.uploads, k)
		}
	}
	return out, nil
}

// ExpireUpload makes the upload id expire now, for tests.
func (s *Store) ExpireUpload(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up := s.uploadByID(id); up != nil {
		up.ExpiresAt = time.Now()
	}
}

// SetUploadWriter makes writer hold the claim on upload id, for tests.
func (s *Store) SetUploadWriter(id int64, writer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up := s.uploadByID(id); up != nil {
		up.writer, up.writerUntil = writer, time.Now().Add(time.Hour)
	}
}
