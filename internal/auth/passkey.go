package auth

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkeys sign users in without a password, with a key that their phone,
// computer or security key keeps and unlocks with a fingerprint, their face
// or a PIN (WebAuthn). A user already signed in makes one, confirming with
// their password. A passkey is a second factor in itself, so two-factor
// sign-in asks no code after one. Each works only on the site (host name)
// it was made on.

// Passkey is one of a user's passkeys.
type Passkey struct {
	ID           int64
	UserID       int64
	Name         string // what it is, e.g. "iPhone"
	CreatedAt    time.Time
	LastUsedAt   time.Time // zero if never
	CredentialID []byte
	Credential   []byte // the webauthn.Credential, as JSON
}

// MaxPasskeys bounds the passkeys of one user.
const MaxPasskeys = 10

// maxPasskeyName bounds the length of a passkey's name.
const maxPasskeyName = 64

// A passkey is made, or used to sign in, within ceremonyTTL of starting.
const (
	ceremonyTTL   = 5 * time.Minute
	maxCeremonies = 10_000
)

var (
	// ErrPasskeyRefused is a passkey, or an answer of the browser, that
	// does not check out.
	ErrPasskeyRefused = errors.New("passkey refused")
	// ErrCeremonyGone is a passkey that took too long to make or use, or
	// was started elsewhere: it starts again.
	ErrCeremonyGone = errors.New("start again")
)

// Site is where passkeys are made and used: the host name, which they are
// bound to, and the origin of the pages that use them.
type Site struct{ Host, Origin string }

func (site Site) webauthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          site.Host,
		RPDisplayName: "goftp",
		RPOrigins:     []string{site.Origin},
		// Passkeys proper: kept by the authenticator, which checks who
		// uses them, so that they can sign in without a username.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
}

// passkeyUser is a user as WebAuthn knows them.
type passkeyUser struct {
	u     *User
	keys  []Passkey
	creds []webauthn.Credential
}

func newPasskeyUser(u *User, keys []Passkey) (*passkeyUser, error) {
	pu := &passkeyUser{u: u, keys: keys}
	for _, k := range keys {
		var cred webauthn.Credential
		if err := json.Unmarshal(k.Credential, &cred); err != nil {
			return nil, fmt.Errorf("passkey %d: %w", k.ID, err)
		}
		pu.creds = append(pu.creds, cred)
	}
	return pu, nil
}

// userHandle is how passkeys name the user id: never reused, and nothing
// else about them.
func userHandle(id int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(id)) }

func (pu *passkeyUser) WebAuthnID() []byte                         { return userHandle(pu.u.ID) }
func (pu *passkeyUser) WebAuthnName() string                       { return pu.u.Username }
func (pu *passkeyUser) WebAuthnDisplayName() string                { return pu.u.Username }
func (pu *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return pu.creds }

// key returns the passkey of the credential id.
func (pu *passkeyUser) key(id []byte) *Passkey {
	for i := range pu.keys {
		if string(pu.keys[i].CredentialID) == string(id) {
			return &pu.keys[i]
		}
	}
	return nil
}

// ceremony is a passkey being made, for user, or used to sign in.
type ceremony struct {
	data    webauthn.SessionData
	site    Site
	user    *User
	expires time.Time
}

// ceremonies are those under way, by token hash.
type ceremonies struct {
	mu sync.Mutex
	m  map[string]*ceremony
}

func (cs *ceremonies) start(c *ceremony) (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	if cs.m == nil {
		cs.m = map[string]*ceremony{}
	}
	if len(cs.m) >= maxCeremonies {
		for k, old := range cs.m {
			if now.After(old.expires) {
				delete(cs.m, k)
			}
		}
		if len(cs.m) >= maxCeremonies {
			return "", ErrBusy
		}
	}
	c.expires = now.Add(ceremonyTTL)
	token := newToken()
	cs.m[string(tokenHash(token))] = c
	return token, nil
}

// take ends the ceremony token and returns it, if it is still under way.
func (cs *ceremonies) take(token string) (*ceremony, bool) {
	if len(token) != 43 {
		return nil, false
	}
	key := string(tokenHash(token))
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[key]
	delete(cs.m, key)
	if !ok || time.Now().After(c.expires) {
		return nil, false
	}
	return c, true
}

// Passkeys lists u's passkeys, oldest first.
func (s *Service) Passkeys(ctx context.Context, u *User) ([]Passkey, error) {
	return s.store.Passkeys(ctx, u.ID)
}

// DeletePasskey deletes u's passkey id (ErrNotFound if u has none of that
// ID).
func (s *Service) DeletePasskey(ctx context.Context, u *User, id int64) error {
	return s.store.DeletePasskey(ctx, u.ID, id)
}

// BeginPasskey starts making a passkey for u at site, after checking their
// password. It returns the options for the browser's
// navigator.credentials.create, as JSON, and a token that FinishPasskey
// takes with the browser's answer. ErrTooMany if u has MaxPasskeys.
func (s *Service) BeginPasskey(ctx context.Context, u *User, password string, site Site) ([]byte, string, error) {
	if err := s.checkPasswordOf(ctx, u, password); err != nil {
		return nil, "", err
	}
	keys, err := s.store.Passkeys(ctx, u.ID)
	if err != nil {
		return nil, "", err
	}
	if len(keys) >= MaxPasskeys {
		return nil, "", ErrTooMany
	}
	pu, err := newPasskeyUser(u, keys)
	if err != nil {
		return nil, "", err
	}
	wa, err := site.webauthn()
	if err != nil {
		return nil, "", err
	}
	// An authenticator that has one of u's passkeys makes no other.
	var exclude []protocol.CredentialDescriptor
	for _, cred := range pu.creds {
		exclude = append(exclude, cred.Descriptor())
	}
	creation, data, err := wa.BeginRegistration(pu, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", err
	}
	token, err := s.ceremonies.start(&ceremony{data: *data, site: site, user: u})
	if err != nil {
		return nil, "", err
	}
	options, err := json.Marshal(creation)
	return options, token, err
}

// FinishPasskey makes the passkey that the ceremony token started, named
// name, from response, the browser's answer as JSON.
func (s *Service) FinishPasskey(ctx context.Context, u *User, token, name string, response []byte) (*Passkey, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxPasskeyName || strings.ContainsFunc(name, unicode.IsControl) {
		return nil, fmt.Errorf("%w: name it in up to %d characters", ErrInvalid, maxPasskeyName)
	}
	c, ok := s.ceremonies.take(token)
	if !ok || c.user == nil || c.user.ID != u.ID {
		return nil, ErrCeremonyGone
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPasskeyRefused, err)
	}
	keys, err := s.store.Passkeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	pu, err := newPasskeyUser(u, keys)
	if err != nil {
		return nil, err
	}
	wa, err := c.site.webauthn()
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(pu, c.data, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPasskeyRefused, err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	pk := &Passkey{UserID: u.ID, Name: name, CredentialID: cred.ID, Credential: raw}
	err = s.store.CreatePasskey(ctx, pk, u.PasswordHash)
	if errors.Is(err, ErrNotFound) {
		// The password changed meanwhile, ending what it made.
		return nil, ErrCeremonyGone
	}
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// BeginPasskeyLogin starts signing in with a passkey at site, whoever has
// it. It returns the options for the browser's navigator.credentials.get,
// as JSON, and a token that PasskeyLogin takes with the browser's answer.
func (s *Service) BeginPasskeyLogin(site Site) ([]byte, string, error) {
	wa, err := site.webauthn()
	if err != nil {
		return nil, "", err
	}
	assertion, data, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	token, err := s.ceremonies.start(&ceremony{data: *data, site: site})
	if err != nil {
		return nil, "", err
	}
	options, err := json.Marshal(assertion)
	return options, token, err
}

// PasskeyLogin signs in with the passkey of response, the browser's answer
// as JSON to the ceremony token, and starts a session for its user.
func (s *Service) PasskeyLogin(ctx context.Context, token string, response []byte) (*Session, error) {
	c, ok := s.ceremonies.take(token)
	if !ok || c.user != nil {
		return nil, ErrCeremonyGone
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPasskeyRefused, err)
	}
	var owner *passkeyUser
	find := func(_, handle []byte) (webauthn.User, error) {
		if len(handle) != 8 {
			return nil, ErrNotFound
		}
		u, err := s.store.UserByID(ctx, int64(binary.BigEndian.Uint64(handle)))
		if err != nil {
			return nil, err
		}
		keys, err := s.store.Passkeys(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if owner, err = newPasskeyUser(u, keys); err != nil {
			return nil, err
		}
		return owner, nil
	}
	wa, err := c.site.webauthn()
	if err != nil {
		return nil, err
	}
	cred, err := wa.ValidateDiscoverableLogin(find, c.data, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPasskeyRefused, err)
	}
	if cred.Authenticator.CloneWarning {
		return nil, fmt.Errorf("%w: its signature counter went back, as if it was copied", ErrPasskeyRefused)
	}
	pk := owner.key(cred.ID)
	if pk == nil {
		return nil, ErrPasskeyRefused
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	if err := s.store.UsePasskey(ctx, pk.ID, raw); err != nil {
		return nil, err
	}
	return s.loginSession(ctx, owner.u, false)
}
