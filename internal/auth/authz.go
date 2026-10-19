package auth

import (
	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Actions checked against the policy.
const (
	ActRead      = "read"      // list directories, download files
	ActWrite     = "write"     // upload new files, create folders
	ActOverwrite = "overwrite" // replace existing files
	ActDelete    = "delete"    // delete and rename files and folders
	ActShare     = "share"     // create links for people without an account
)

// Actions are the actions rules may allow, besides "*" for all of them.
var Actions = []string{ActRead, ActWrite, ActOverwrite, ActDelete, ActShare}

// Anonymous is the subject for requests without a session.
const Anonymous = "anonymous"

// Subject returns the policy subject of a user. The prefix keeps user names
// apart from role names.
func Subject(username string) string { return "user:" + username }

// Objects are URL paths; directories end in "/". "/docs/*" covers /docs/
// and everything below it, and a leading "!" denies. The model stores the
// rules and roles; Rules decides, as its matcher cannot weigh denials.
const modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (p.act == "*" || r.act == p.act)
`

// DefaultPolicies are the rules the first migration seeds.
var DefaultPolicies = [][]string{
	{"p", "user", "/*", ActRead},
	{"p", "operator", "/*", ActWrite},
	{"p", "admin", "/*", ActOverwrite},
	{"p", "admin", "/*", ActDelete},
	{"p", "admin", "/*", ActShare},
	{"p", "superadmin", "/*", "*"},
	{"g", "operator", "user"},
	{"g", "admin", "operator"},
	{"g", "superadmin", "admin"},
}

// NewEnforcer creates an enforcer backed by adapter, or an in-memory one
// holding DefaultPolicies when adapter is nil.
func NewEnforcer(adapter persist.Adapter) (*casbin.SyncedEnforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, err
	}
	if adapter != nil {
		return casbin.NewSyncedEnforcer(m, adapter)
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, err
	}
	for _, rule := range DefaultPolicies {
		if err := persist.LoadPolicyArray(rule, e.GetModel()); err != nil {
			return nil, err
		}
	}
	if err := e.BuildRoleLinks(); err != nil {
		return nil, err
	}
	return e, nil
}
