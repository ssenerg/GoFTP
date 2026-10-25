package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3"
	"go.uber.org/zap"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	// The reasons are for logs; clients only learn ErrInvalidCredentials.
	ErrNoSuchUser       = fmt.Errorf("%w: no such user", ErrInvalidCredentials)
	errWrongPassword    = fmt.Errorf("%w: wrong password", ErrInvalidCredentials)
	errChangedMeanwhile = fmt.Errorf("%w: the password changed meanwhile", ErrInvalidCredentials)
	ErrSamePassword     = fmt.Errorf("%w: the new password must differ from the current one", ErrWeakPassword)
	ErrBusy             = errors.New("too many password checks in progress")
)

// hashWait bounds how long a password check waits for a free hashing slot.
var hashWait = 5 * time.Second

// Service authenticates users with sessions and authorizes their requests
// with Casbin.
type Service struct {
	store    Store
	enforcer *casbin.SyncedEnforcer
	ttl      time.Duration

	// hashing bounds concurrent Argon2 runs, which take 19 MiB each.
	hashing   chan struct{}
	dummyOnce sync.Once
	dummy     string

	homes atomic.Value // the folder of users' homes (see SetHomes)
	fold  atomic.Value // how rules compare paths (see SetFold)

	challenges challenges // sign-ins that wait for a two-factor code
}

func NewService(store Store, enforcer *casbin.SyncedEnforcer, sessionTTL time.Duration) *Service {
	return &Service{
		store:    store,
		enforcer: enforcer,
		ttl:      sessionTTL,
		hashing:  make(chan struct{}, runtime.GOMAXPROCS(0)),
	}
}

// Enforcer exposes the policy enforcer.
func (s *Service) Enforcer() *casbin.SyncedEnforcer { return s.enforcer }

func (s *Service) acquireHashing(ctx context.Context) (func(), error) {
	t := time.NewTimer(hashWait)
	defer t.Stop()
	select {
	case s.hashing <- struct{}{}:
		return func() { <-s.hashing }, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// verify checks password against u's hash. For unknown users (u == nil) it
// verifies against a dummy hash, so response times do not reveal which
// usernames exist.
func (s *Service) verify(ctx context.Context, u *User, password string) (bool, error) {
	release, err := s.acquireHashing(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if u == nil {
		s.dummyOnce.Do(func() { s.dummy = hashPassword(rand.Text()) })
		verifyPassword(s.dummy, password)
		return false, nil
	}
	if u.MustChangePassword {
		password = forgiveTemporary(password)
	}
	return verifyPassword(u.PasswordHash, password), nil
}

func (s *Service) hash(ctx context.Context, password string) (string, error) {
	release, err := s.acquireHashing(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return hashPassword(password), nil
}

// NormalizeUsername lowercases and trims a username as typed by a person.
func NormalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Session is a signed-in user with their session token.
type Session struct {
	Token   string
	Expires time.Time
	User    *User
	// RecoveryCode is set when the user signed in with a recovery code.
	RecoveryCode bool
}

// Login checks the credentials and starts a session; for users with
// two-factor sign-in, see LoginWithCode.
func (s *Service) Login(ctx context.Context, username, password string) (*Session, error) {
	return s.LoginWithCode(ctx, username, password, "")
}

// checkLogin checks the credentials and returns their user.
func (s *Service) checkLogin(ctx context.Context, username, password string) (*User, error) {
	username = NormalizeUsername(username)
	if checkUsername(username) != nil {
		return nil, ErrNoSuchUser
	}
	if password == "" || len(password) > MaxPasswordLength {
		return nil, errWrongPassword
	}
	u, err := s.store.UserByName(ctx, username)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	ok, err := s.verify(ctx, u, password)
	switch {
	case err != nil:
		return nil, err
	case u == nil:
		return nil, ErrNoSuchUser
	case !ok:
		return nil, errWrongPassword
	}
	return u, nil
}

func (s *Service) newSession(ctx context.Context, u *User) (*Session, error) {
	sess := &Session{Token: newToken(), Expires: time.Now().Add(s.ttl), User: u}
	if err := s.store.CreateSession(ctx, tokenHash(sess.Token), u, sess.Expires); err != nil {
		return nil, err
	}
	return sess, nil
}

// newToken returns a random session or link token: 43 characters for 256
// bits.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Authenticate returns the user of a live session, or ErrNotFound.
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	if len(token) != 43 {
		return nil, ErrNotFound
	}
	return s.store.SessionUser(ctx, tokenHash(token))
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, tokenHash(token))
}

// ChangePassword replaces u's password after checking the current one. All
// of u's sessions end and a new one starts.
func (s *Service) ChangePassword(ctx context.Context, u *User, current, next string) (*Session, error) {
	if len(current) > MaxPasswordLength {
		return nil, errWrongPassword
	}
	ok, err := s.verify(ctx, u, current)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errWrongPassword
	}
	if err := CheckPassword(u.Username, next); err != nil {
		return nil, err
	}
	if next == current {
		return nil, ErrSamePassword
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetPassword(ctx, u.ID, hash, false); err != nil {
		return nil, err
	}
	changed := *u
	changed.PasswordHash, changed.MustChangePassword = hash, false
	return s.newSession(ctx, &changed)
}

// Allowed reports whether u (nil for anonymous) may perform act on obj.
// For many checks, RulesFor gathers the rules once.
func (s *Service) Allowed(u *User, obj, act string) (bool, error) {
	r, err := s.RulesFor(context.Background(), u)
	if err != nil {
		return false, err
	}
	return r.Allow(obj, act), nil
}

// IsSuperadmin reports whether username holds the role that administers
// users and rules. It goes by the role, not by rules, so that no rule
// change can lock administrators out.
func (s *Service) IsSuperadmin(username string) bool {
	ok, err := s.enforcer.HasRoleForUser(Subject(username), Superadmin)
	return ok && err == nil
}

// Role returns the roles assigned to username, comma separated.
func (s *Service) Role(username string) string {
	roles, _ := s.enforcer.GetRolesForUser(Subject(username))
	return strings.Join(roles, ",")
}

// PurgeExpired deletes expired sessions and share links periodically until
// ctx ends.
func (s *Service) PurgeExpired(ctx context.Context, every time.Duration, log *zap.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.store.DeleteExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			log.Warn("purge sessions", zap.Error(err))
		}
		if err := s.store.DeleteExpiredShares(ctx); err != nil && ctx.Err() == nil {
			log.Warn("purge share links", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
