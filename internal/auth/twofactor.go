package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Two-factor sign-in asks users who turn it on for a code from an
// authenticator app after their password (TOTP, RFC 6238, as such apps
// expect: HMAC-SHA1, 30-second steps, 6 digits), or for one of their
// recovery codes, each of which works once. No code works twice. App
// passwords sign in without one: each is a secret of its own, for one app,
// and is revoked alone.
const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew is how many steps before and after now are accepted too,
	// for clocks that drift.
	totpSkew = 1
	// Recovery codes have 10 letters and digits, 50 bits; they are shown in
	// two groups of five.
	recoveryCodes      = 10
	recoveryCodeLength = 10
	// A sign-in that waits for a code may get it for a while, a few times.
	challengeTTL   = 5 * time.Minute
	challengeTries = 5
	maxChallenges  = 10_000
)

var (
	// ErrWrongCode is a two-factor code that is wrong, or was used already.
	ErrWrongCode = fmt.Errorf("%w: wrong two-factor code", ErrInvalidCredentials)
	// ErrChallengeGone is a sign-in that waited for a code too long, or got
	// too many wrong ones: it starts again with the password.
	ErrChallengeGone = errors.New("sign in again")
)

// CodeNeeded is the error of a sign-in of a user with two-factor sign-in
// that came without a code. Challenge stands for the password checked:
// ContinueLogin takes it with a code, for a while.
type CodeNeeded struct{ Challenge string }

func (e *CodeNeeded) Error() string { return "a two-factor code is needed" }

// challenge is a sign-in that waits for a code.
type challenge struct {
	user    *User
	expires time.Time
	tries   int
}

// challenges are the sign-ins that wait for a code, by token hash.
type challenges struct {
	mu sync.Mutex
	m  map[string]*challenge
}

// start keeps a sign-in of u waiting for a code, and returns its token.
func (cs *challenges) start(u *User) (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	if cs.m == nil {
		cs.m = map[string]*challenge{}
	}
	if len(cs.m) >= maxChallenges {
		for k, c := range cs.m {
			if now.After(c.expires) {
				delete(cs.m, k)
			}
		}
		if len(cs.m) >= maxChallenges {
			return "", ErrBusy
		}
	}
	token := newToken()
	cs.m[string(tokenHash(token))] = &challenge{user: u, expires: now.Add(challengeTTL)}
	return token, nil
}

// try counts a try of the sign-in token and returns its user, unless it is
// gone; done ends it.
func (cs *challenges) try(token string) (u *User, done func(), err error) {
	key := string(tokenHash(token))
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[key]
	if ok && time.Now().After(c.expires) {
		delete(cs.m, key)
		ok = false
	}
	if !ok {
		return nil, nil, ErrChallengeGone
	}
	if c.tries++; c.tries >= challengeTries {
		delete(cs.m, key)
	}
	return c.user, func() {
		cs.mu.Lock()
		delete(cs.m, key)
		cs.mu.Unlock()
	}, nil
}

// LoginWithCode is Login for a user who may have two-factor sign-in: it
// then also needs code, from their app or a recovery code. Without one, it
// returns a *CodeNeeded.
func (s *Service) LoginWithCode(ctx context.Context, username, password, code string) (*Session, error) {
	u, err := s.checkLogin(ctx, username, password)
	if err != nil {
		return nil, err
	}
	recovery := false
	if u.TwoFactor {
		if strings.TrimSpace(code) == "" {
			token, err := s.challenges.start(u)
			if err != nil {
				return nil, err
			}
			return nil, &CodeNeeded{Challenge: token}
		}
		if recovery, err = s.checkCode(ctx, u, code); err != nil {
			return nil, err
		}
	}
	return s.loginSession(ctx, u, recovery)
}

// ContinueLogin goes on with the sign-in that challenge stands for (see
// CodeNeeded), given code. ErrWrongCode leaves a few more tries;
// ErrChallengeGone means signing in again.
func (s *Service) ContinueLogin(ctx context.Context, challenge, code string) (*Session, error) {
	if len(challenge) != 43 {
		return nil, ErrChallengeGone
	}
	u, done, err := s.challenges.try(challenge)
	if err != nil {
		return nil, err
	}
	recovery, err := s.checkCode(ctx, u, code)
	if err != nil {
		return nil, err
	}
	done()
	return s.loginSession(ctx, u, recovery)
}

func (s *Service) loginSession(ctx context.Context, u *User, recovery bool) (*Session, error) {
	sess, err := s.newSession(ctx, u)
	if errors.Is(err, ErrNotFound) {
		// Changed (or the user was deleted) since it was checked.
		return nil, errChangedMeanwhile
	}
	if err != nil {
		return nil, err
	}
	sess.RecoveryCode = recovery
	return sess, nil
}

// checkCode checks code, from u's app or one of their recovery codes, and
// uses it up. It reports whether it was a recovery code. Without two-factor
// sign-in, as it was turned off meanwhile, any code will do.
func (s *Service) checkCode(ctx context.Context, u *User, code string) (bool, error) {
	tf, err := s.store.TwoFactor(ctx, u.ID)
	if err != nil {
		return false, err
	}
	if tf.Secret == nil {
		return false, nil
	}
	code = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(code)))
	if step, ok := matchTOTP(tf.Secret, code, time.Now(), tf.Step); ok {
		used, err := s.store.UseTwoFactorStep(ctx, u.ID, step)
		if err != nil || !used {
			return false, cmpErr(err, ErrWrongCode)
		}
		return false, nil
	}
	if len(code) != recoveryCodeLength || strings.ContainsFunc(code, func(r rune) bool { return !('a' <= r && r <= 'z' || '2' <= r && r <= '7') }) {
		return false, ErrWrongCode
	}
	used, err := s.store.UseRecoveryCode(ctx, u.ID, tokenHash(code))
	if err != nil || !used {
		return false, cmpErr(err, ErrWrongCode)
	}
	return true, nil
}

// cmpErr returns err, or otherwise if err is nil.
func cmpErr(err, otherwise error) error {
	if err != nil {
		return err
	}
	return otherwise
}

// matchTOTP returns the time step around now for which code is the code of
// secret, if one is, after the step last.
func matchTOTP(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != totpDigits || strings.ContainsFunc(code, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0, false
	}
	at := now.Unix() / totpPeriod
	for step := at - totpSkew; step <= at+totpSkew; step++ {
		if step > last && hmac.Equal([]byte(totpCode(secret, step)), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// totpCode is the code of secret for the time step (RFC 4226, 5.3).
func totpCode(secret []byte, step int64) string {
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
	code := strconv.Itoa(int(n % 1_000_000))
	return strings.Repeat("0", totpDigits-len(code)) + code
}

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TwoFactorState says how far a user is with two-factor sign-in.
type TwoFactorState struct {
	On bool
	// Pending is the secret being set up, in base32, as apps take it; ""
	// if none.
	Pending       string
	RecoveryCodes int // left
}

// TwoFactorOf says how far u is with two-factor sign-in.
func (s *Service) TwoFactorOf(ctx context.Context, u *User) (*TwoFactorState, error) {
	tf, err := s.store.TwoFactor(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	st := &TwoFactorState{On: tf.Secret != nil, RecoveryCodes: tf.RecoveryCodes}
	if tf.Pending != nil && tf.Secret == nil {
		st.Pending = secretEncoding.EncodeToString(tf.Pending)
	}
	return st, nil
}

// StartTwoFactor makes a new secret for u to add to their app, and returns
// it in base32: two-factor sign-in is on once ConfirmTwoFactor gets a code
// of it. ErrInvalid if it is on already.
func (s *Service) StartTwoFactor(ctx context.Context, u *User) (string, error) {
	tf, err := s.store.TwoFactor(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if tf.Secret != nil {
		return "", fmt.Errorf("%w: two-factor sign-in is on already", ErrInvalid)
	}
	secret := make([]byte, 20)
	_, _ = rand.Read(secret)
	if err := s.store.SetTwoFactorPending(ctx, u.ID, secret); err != nil {
		return "", err
	}
	return secretEncoding.EncodeToString(secret), nil
}

// ConfirmTwoFactor turns two-factor sign-in on for u, given a code of the
// secret StartTwoFactor made (ErrWrongCode otherwise; ErrNotFound if none
// is being set up). It returns their recovery codes, which are not kept,
// and a new session: all of u's sessions end.
func (s *Service) ConfirmTwoFactor(ctx context.Context, u *User, code string) ([]string, *Session, error) {
	tf, err := s.store.TwoFactor(ctx, u.ID)
	switch {
	case err != nil:
		return nil, nil, err
	case tf.Secret != nil:
		return nil, nil, fmt.Errorf("%w: two-factor sign-in is on already", ErrInvalid)
	case tf.Pending == nil:
		return nil, nil, ErrNotFound
	}
	step, ok := matchTOTP(tf.Pending, strings.ReplaceAll(strings.TrimSpace(code), " ", ""), time.Now(), 0)
	if !ok {
		return nil, nil, ErrWrongCode
	}
	codes, hashes := newRecoveryCodes()
	if err := s.store.EnableTwoFactor(ctx, u.ID, tf.Pending, step, hashes); err != nil {
		return nil, nil, err
	}
	on := *u
	on.TwoFactor = true
	sess, err := s.newSession(ctx, &on)
	if err != nil {
		return nil, nil, err
	}
	return codes, sess, nil
}

// NewRecoveryCodes replaces u's recovery codes, after checking their
// password, and returns them: they are not kept. ErrInvalid if two-factor
// sign-in is off.
func (s *Service) NewRecoveryCodes(ctx context.Context, u *User, password string) ([]string, error) {
	if err := s.checkPasswordOf(ctx, u, password); err != nil {
		return nil, err
	}
	codes, hashes := newRecoveryCodes()
	err := s.store.SetRecoveryCodes(ctx, u.ID, hashes)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: two-factor sign-in is off", ErrInvalid)
	}
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableTwoFactor turns two-factor sign-in off for u, after checking their
// password.
func (s *Service) DisableTwoFactor(ctx context.Context, u *User, password string) error {
	if err := s.checkPasswordOf(ctx, u, password); err != nil {
		return err
	}
	return s.store.DisableTwoFactor(ctx, u.ID)
}

// ResetTwoFactor turns two-factor sign-in off for the user username, for
// administrators: for a user who lost their app and their recovery codes.
// It reports whether it was on.
func (s *Service) ResetTwoFactor(ctx context.Context, username string) (bool, error) {
	u, err := s.store.UserByName(ctx, NormalizeUsername(username))
	if err != nil {
		return false, err
	}
	if !u.TwoFactor {
		return false, nil
	}
	return true, s.store.DisableTwoFactor(ctx, u.ID)
}

// checkPasswordOf checks the password of the signed-in u.
func (s *Service) checkPasswordOf(ctx context.Context, u *User, password string) error {
	if password == "" || len(password) > MaxPasswordLength {
		return errWrongPassword
	}
	ok, err := s.verify(ctx, u, password)
	if err != nil {
		return err
	}
	if !ok {
		return errWrongPassword
	}
	return nil
}

// newRecoveryCodes makes recovery codes, as shown and as kept.
func newRecoveryCodes() (codes []string, hashes [][]byte) {
	for range recoveryCodes {
		raw := strings.ToLower(rand.Text()[:recoveryCodeLength])
		codes = append(codes, raw[:5]+"-"+raw[5:])
		hashes = append(hashes, tokenHash(raw))
	}
	return codes, hashes
}

// OTPAuthURI is the URI that authenticator apps take, as a QR code, for
// the secret (in base32) of the user username, at the site issuer.
func OTPAuthURI(issuer, username, secret string) string {
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {strconv.Itoa(totpDigits)}, "period": {strconv.Itoa(totpPeriod)}}
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(username) + "?" + q.Encode()
}
