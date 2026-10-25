package server

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/config"
)

const (
	adminPath = "/.admin/"
	usersPath = adminPath + "users"
	rulesPath = adminPath + "rules"
)

type adminPage struct {
	page
	Tab      string // users or rules
	Roles    []string
	Actions  []string
	Users    []adminUser
	Rules    []adminRule
	Subjects []subject
	Notice   string
	Error    string
	Secret   *secret // a temporary password, shown once
	Homes    string  // the folder of homes, whose rules are built in
	Quota    string  // how much a home may hold by default, e.g. "10GiB"; "" for no limit
	NoTrash  bool    // deleting is for good
}

type adminUser struct {
	Name, Role       string
	MustChange, Self bool
	TwoFactor        bool
	Added, AddedISO  string
	Quota            string // how much their home may hold, as set: "" for the default, "none" for no limit
}

type adminRule struct {
	Subject, Who, Action string
	Object               string // as stored: "!" first for denials
	Path                 string // as shown
	Deny                 bool
}

type subject struct {
	Value, Label, Group string
}

type secret struct {
	User, Password string
	New            bool
}

// The notices that redirects after a change may ask for. Only these texts
// can be shown, so links cannot make the page say something else.
var adminNotices = map[string]string{
	"role":         "The role was changed.",
	"quota":        "The home quota was set.",
	"deleted":      "The user was deleted.",
	"deleted-home": "The user was deleted. Their home went to the trash, where a superadmin can restore it for them.",
	"deleted-all":  "The user was deleted, and their home with everything in it, as the trash is off.",
	"two-factor":   "Two-factor sign-in is off for them: their password alone signs them in, until they turn it on again.",
	"rule-added":   "The rule was added.",
	"rule-removed": "The rule was removed.",
}

// superadmin reports whether the visitor is a superadmin. Anyone else is
// answered already: anonymous visitors are sent to sign in, others refused.
func (s *Server) superadmin(c fiber.Ctx) (bool, error) {
	u := userOf(c)
	if u == nil {
		return false, s.deny(c)
	}
	if !s.auth.IsSuperadmin(u.Username) {
		return false, fiber.ErrForbidden
	}
	return true, nil
}

func (s *Server) adminHome(c fiber.Ctx) error {
	if ok, err := s.superadmin(c); !ok {
		return err
	}
	return s.redirect(c, usersPath)
}

func (s *Server) usersPage(c fiber.Ctx) error {
	if ok, err := s.superadmin(c); !ok {
		return err
	}
	return s.renderAdmin(c, fiber.StatusOK, "users", adminNotices[c.Query("done")], "", nil)
}

func (s *Server) rulesPage(c fiber.Ctx) error {
	if ok, err := s.superadmin(c); !ok {
		return err
	}
	return s.renderAdmin(c, fiber.StatusOK, "rules", adminNotices[c.Query("done")], "", nil)
}

// usersAction adds users, gives them new temporary passwords, changes their
// roles, turns two-factor sign-in off for those who lost their app, and
// deletes them. Superadmins cannot change their own account here,
// so they cannot lock themselves out.
func (s *Server) usersAction(c fiber.Ctx) error {
	if ok, err := s.superadmin(c); !ok {
		return err
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	me := userOf(c).Username
	name, role := auth.NormalizeUsername(form["user"]), form["role"]
	fail := func(status int, msg string) error { return s.renderAdmin(c, status, "users", "", msg, nil) }
	if action := form["action"]; action != "add" && action != "quota" && name == me {
		return fail(fiber.StatusBadRequest, "You cannot change your own account here. To choose a new password, use Change password in your menu.")
	}
	ctx, cancel := dbContext(c)
	defer cancel()

	switch form["action"] {
	case "add":
		password, err := s.auth.CreateUser(ctx, name, role)
		if err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.logAdmin(c, "user added", zap.String("target", name), zap.String("role", role))
		return s.renderAdmin(c, fiber.StatusOK, "users", "", "", &secret{User: name, Password: password, New: true})
	case "password":
		password, err := s.auth.ResetPassword(ctx, name)
		if err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.logAdmin(c, "password reset", zap.String("target", name))
		return s.renderAdmin(c, fiber.StatusOK, "users", "", "", &secret{User: name, Password: password})
	case "quota":
		quota, err := config.ParseQuota(form["quota"])
		if err != nil {
			return fail(fiber.StatusBadRequest, "Give a home quota as a size such as 10 GiB, none for no limit, or nothing for the default.")
		}
		if err := s.auth.SetHomeQuota(ctx, name, quota); err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.recount(name)
		s.logAdmin(c, "home quota set", zap.String("target", name), zap.String("quota", form["quota"]))
		return s.redirect(c, usersPath+"?done=quota")
	case "two-factor-off":
		if _, err := s.auth.ResetTwoFactor(ctx, name); err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.logAdmin(c, "two-factor sign-in turned off", zap.String("target", name))
		return s.redirect(c, usersPath+"?done=two-factor")
	case "role":
		if err := s.auth.SetRole(ctx, name, role); err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.logAdmin(c, "role changed", zap.String("target", name), zap.String("role", role))
		return s.redirect(c, usersPath+"?done=role")
	case "delete":
		if err := s.auth.DeleteUser(ctx, name); err != nil {
			return s.adminFailure(c, "users", err)
		}
		s.logAdmin(c, "user deleted", zap.String("target", name))
		// Nothing of it may reach a new user of the same name.
		moved, err := s.trashHomeOf(me, name)
		if err != nil {
			s.log.Error("move home to the trash", zap.String("user", name), zap.Error(err))
			return s.renderAdmin(c, fiber.StatusOK, "users", "", "The user was deleted, but their home could not be moved to the trash: "+
				"it stays private, and goes there once a user of that name signs in.", nil)
		}
		switch {
		case moved && s.cfg.Trash.Keep == 0:
			s.logAdmin(c, "home deleted", zap.String("target", name))
			return s.redirect(c, usersPath+"?done=deleted-all")
		case moved:
			s.logAdmin(c, "home moved to the trash", zap.String("target", name))
			return s.redirect(c, usersPath+"?done=deleted-home")
		}
		return s.redirect(c, usersPath+"?done=deleted")
	}
	return fiber.ErrBadRequest
}

// rulesAction adds and removes access rules.
func (s *Server) rulesAction(c fiber.Ctx) error {
	if ok, err := s.superadmin(c); !ok {
		return err
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	sub, obj, act := strings.TrimSpace(form["subject"]), strings.TrimSpace(form["path"]), form["act"]
	fail := func(status int, msg string) error { return s.renderAdmin(c, status, "rules", "", msg, nil) }
	switch form["action"] {
	case "add":
		// A denial is chosen, or written as in a .gitignore.
		switch form["effect"] {
		case "deny":
			if !strings.HasPrefix(obj, auth.DenyPrefix) {
				obj = auth.DenyPrefix + obj
			}
		case "allow", "":
		default:
			return fiber.ErrBadRequest
		}
		ok, err := s.auth.AddPolicy(sub, obj, act)
		switch {
		case err != nil:
			return s.adminFailure(c, "rules", err)
		case !ok:
			return fail(fiber.StatusConflict, "This rule exists already.")
		}
		s.logAdmin(c, "rule added", zap.String("subject", sub), zap.String("path", obj), zap.String("action", act))
		return s.redirect(c, rulesPath+"?done=rule-added")
	case "remove":
		ok, err := s.auth.RemovePolicy(sub, obj, act)
		switch {
		case err != nil:
			return err
		case !ok:
			return fail(fiber.StatusNotFound, "There is no such rule.")
		}
		s.logAdmin(c, "rule removed", zap.String("subject", sub), zap.String("path", obj), zap.String("action", act))
		return s.redirect(c, rulesPath+"?done=rule-removed")
	}
	return fiber.ErrBadRequest
}

// adminFailure shows why a change was refused: the auth service's errors
// name the problem in words meant for administrators.
func (s *Server) adminFailure(c fiber.Ctx, tab string, err error) error {
	status := fiber.StatusBadRequest
	switch {
	case errors.Is(err, auth.ErrExists):
		status = fiber.StatusConflict
	case errors.Is(err, auth.ErrNotFound):
		status = fiber.StatusNotFound
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidRole),
		errors.Is(err, auth.ErrInvalidSubject), errors.Is(err, auth.ErrInvalidObject), errors.Is(err, auth.ErrInvalidAction):
	default:
		return err
	}
	msg := err.Error()
	return s.renderAdmin(c, status, tab, "", strings.ToUpper(msg[:1])+msg[1:]+".", nil)
}

func (s *Server) logAdmin(c fiber.Ctx, msg string, fields ...zap.Field) {
	s.log.Info(msg, append([]zap.Field{zap.String("ip", c.IP()), zap.String("by", visitor(c))}, fields...)...)
}

func (s *Server) renderAdmin(c fiber.Ctx, status int, tab, notice, failure string, shown *secret) error {
	data := adminPage{
		page: s.page(c, "Administration"), Tab: tab, Roles: auth.Roles, Homes: s.cfg.Homes.Path,
		NoTrash: s.cfg.Trash.Keep == 0, Quota: quotaText(int64(s.cfg.Homes.Quota)),
		Actions: append(slices.Clone(auth.Actions), "*"),
		Notice:  notice, Error: failure, Secret: shown,
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	users, err := s.auth.Users(ctx)
	if err != nil {
		return err
	}
	me := userOf(c).Username
	for _, u := range users {
		data.Users = append(data.Users, adminUser{
			Name: u.Username, Role: u.Role, MustChange: u.MustChangePassword, Self: u.Username == me, TwoFactor: u.TwoFactor,
			Added: u.CreatedAt.UTC().Format("Jan 2, 2006"), AddedISO: isoTime(u.CreatedAt),
		})
		if q := u.HomeQuota; q != nil {
			data.Users[len(data.Users)-1].Quota = cmp.Or(quotaText(*q), "none")
		}
	}
	slices.SortFunc(data.Users, func(a, b adminUser) int { return strings.Compare(a.Name, b.Name) })

	for _, r := range auth.Roles {
		data.Subjects = append(data.Subjects, subject{Value: r, Label: r, Group: "Roles"})
	}
	data.Subjects = append(data.Subjects, subject{Value: auth.Anonymous, Label: "everyone, also signed out", Group: "Everyone"})
	for _, u := range data.Users {
		data.Subjects = append(data.Subjects, subject{Value: auth.Subject(u.Name), Label: u.Name, Group: "Users"})
	}
	perms, _, err := s.auth.Policies()
	if err != nil {
		return err
	}
	for _, p := range perms {
		if len(p) < 3 {
			continue
		}
		path, deny := strings.CutPrefix(p[1], auth.DenyPrefix)
		data.Rules = append(data.Rules, adminRule{Subject: p[0], Who: who(p[0]), Object: p[1], Path: path, Deny: deny, Action: p[2]})
	}
	slices.SortFunc(data.Rules, func(a, b adminRule) int {
		return strings.Compare(a.Subject+"\x00"+a.Path+"\x00"+a.Object+"\x00"+a.Action, b.Subject+"\x00"+b.Path+"\x00"+b.Object+"\x00"+b.Action)
	})
	return s.render(c, status, "admin", data)
}

// who names the subject of a rule for people.
func who(sub string) string {
	if name, ok := strings.CutPrefix(sub, "user:"); ok {
		return name
	}
	if sub == auth.Anonymous {
		return "everyone"
	}
	return sub + " (role)"
}

// quotaText writes the quota n, e.g. "10GiB"; "" for 0, no limit.
func quotaText(n int64) string {
	if n == 0 {
		return ""
	}
	return config.ByteSize(n).String()
}
