package auth

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

var (
	ErrInvalidSubject = fmt.Errorf("subject must be a role (%s), %q or \"user:<name>\"", strings.Join(Roles, ", "), Anonymous)
	ErrInvalidObject  = errors.New(`path must be a clean absolute URL path, optionally ending in "/*" and starting with "!" to deny, e.g. "/docs/*" or "!/docs/private/*"`)
	ErrInvalidAction  = fmt.Errorf("action must be %s or *", strings.Join(Actions, ", "))
)

// UserInfo is a user with their roles.
type UserInfo struct {
	User
	Role string
}

// CreateUser adds a user with a role and returns their temporary password,
// which has to be changed at the first login.
func (s *Service) CreateUser(ctx context.Context, username, role string) (string, error) {
	username = NormalizeUsername(username)
	if err := checkUsername(username); err != nil {
		return "", err
	}
	if err := checkRole(role); err != nil {
		return "", err
	}
	password := TemporaryPassword()
	hash, err := s.hash(ctx, password)
	if err != nil {
		return "", err
	}
	id, err := s.store.CreateUser(ctx, username, hash)
	if errors.Is(err, ErrExists) {
		return "", fmt.Errorf("user %q: %w", username, err)
	}
	if err != nil {
		return "", err
	}
	if _, err := s.enforcer.AddRoleForUser(Subject(username), role); err != nil {
		// The rule may have been stored even so.
		_, rerr := s.enforcer.DeleteRolesForUser(Subject(username))
		return "", errors.Join(err, rerr, s.store.DeleteUser(ctx, id))
	}
	return password, nil
}

func (s *Service) user(ctx context.Context, username string) (*User, error) {
	u, err := s.store.UserByName(ctx, NormalizeUsername(username))
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("user %q: %w", username, err)
	}
	return u, err
}

// ResetPassword sets a new temporary password and ends the user's sessions
// and share links: if the account was taken over, nothing made with it
// keeps working.
func (s *Service) ResetPassword(ctx context.Context, username string) (string, error) {
	u, err := s.user(ctx, username)
	if err != nil {
		return "", err
	}
	password := TemporaryPassword()
	hash, err := s.hash(ctx, password)
	if err != nil {
		return "", err
	}
	if err := s.store.SetPassword(ctx, u.ID, hash, true); err != nil {
		return "", err
	}
	return password, nil
}

// SetRole replaces the user's roles with role. The new role is added
// first, so that running servers never see the user without one.
func (s *Service) SetRole(ctx context.Context, username, role string) error {
	if err := checkRole(role); err != nil {
		return err
	}
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	sub := Subject(u.Username)
	if _, err := s.enforcer.AddRoleForUser(sub, role); err != nil {
		return err
	}
	roles, err := s.enforcer.GetRolesForUser(sub)
	if err != nil {
		return err
	}
	for _, r := range roles {
		if r != role {
			if _, err := s.enforcer.DeleteRoleForUser(sub, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// DeleteUser removes the user, their policies and sessions. Policies go
// first, so a failure leaves the user without access rather than orphaned
// rules for a future user of the same name.
func (s *Service) DeleteUser(ctx context.Context, username string) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	if _, err := s.enforcer.DeleteUser(Subject(u.Username)); err != nil {
		return err
	}
	return s.store.DeleteUser(ctx, u.ID)
}

func (s *Service) Users(ctx context.Context) ([]UserInfo, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserInfo, len(users))
	for i, u := range users {
		out[i] = UserInfo{User: u, Role: s.Role(u.Username)}
	}
	return out, nil
}

// Policies returns the permission rules followed by the role rules, in
// Casbin's CSV form without the policy type.
func (s *Service) Policies() (perms, roles [][]string, err error) {
	if perms, err = s.enforcer.GetPolicy(); err != nil {
		return nil, nil, err
	}
	roles, err = s.enforcer.GetGroupingPolicy()
	return perms, roles, err
}

// AddPolicy allows sub to perform act on the paths matching obj, or with
// obj starting with DenyPrefix, denies it (see Rules).
func (s *Service) AddPolicy(sub, obj, act string) (bool, error) {
	if err := checkRule(sub, obj, act); err != nil {
		return false, err
	}
	return s.enforcer.AddPolicy(sub, obj, act)
}

func (s *Service) RemovePolicy(sub, obj, act string) (bool, error) {
	return s.enforcer.RemovePolicy(sub, obj, act)
}

func checkRule(sub, obj, act string) error {
	if name, ok := strings.CutPrefix(sub, "user:"); ok {
		if checkUsername(name) != nil {
			return ErrInvalidSubject
		}
	} else if sub != Anonymous && !slices.Contains(Roles, sub) {
		return ErrInvalidSubject
	}
	if act != "*" && !slices.Contains(Actions, act) {
		return ErrInvalidAction
	}
	// "*" makes the text before it a plain prefix, so "/pub*" would also
	// cover "/public-archive/".
	base, wildcard := strings.CutSuffix(strings.TrimPrefix(obj, DenyPrefix), "*")
	if !strings.HasPrefix(base, "/") || (wildcard && !strings.HasSuffix(base, "/")) || strings.ContainsAny(base, "*\\") ||
		strings.ContainsFunc(obj, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ErrInvalidObject
	}
	clean := path.Clean(base)
	if strings.HasSuffix(base, "/") && clean != "/" {
		clean += "/"
	}
	if clean != base {
		return ErrInvalidObject
	}
	return nil
}
