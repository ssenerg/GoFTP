package auth

import "strings"

// DenyPrefix starts the paths of rules that deny, as "!" does in a
// .gitignore: "!/private/*" keeps its subject out of /private/.
const DenyPrefix = "!"

// Rules are the rules that apply to one visitor, ready to be checked many
// times, e.g. for every entry of a listing.
//
// Of the rules that match a path and an action, the one for the longest
// path decides; an exact path is longer than the same path ending in "*".
// Between rules for the same path, a user's own rules come before their
// roles' rules, and a role's rules before those of the roles it inherits.
// Between rules that are still equal, a denial comes before an allowance.
// Signed-in users may also do whatever the rules for everyone allow.
type Rules struct {
	own, anonymous []rule
}

type rule struct {
	base     string // the path, without "!" and "*"
	wildcard bool   // base and everything below it, rather than base alone
	deny     bool
	act      string
	distance int // 0 for the user's own rules, 1 for their roles', and so on
}

// RulesFor gathers the rules that apply to u, nil for anonymous visitors.
func (s *Service) RulesFor(u *User) (*Rules, error) {
	policies, err := s.enforcer.GetPolicy()
	if err != nil {
		return nil, err
	}
	r := &Rules{anonymous: compile(policies, map[string]int{Anonymous: 0})}
	if u != nil {
		distances, err := s.distances(Subject(u.Username))
		if err != nil {
			return nil, err
		}
		r.own = compile(policies, distances)
	}
	return r, nil
}

// distances maps sub and the roles it holds, directly or through other
// roles, to how many steps away from sub they are.
func (s *Service) distances(sub string) (map[string]int, error) {
	distances := map[string]int{sub: 0}
	for queue := []string{sub}; len(queue) > 0; queue = queue[1:] {
		roles, err := s.enforcer.GetRolesForUser(queue[0])
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if _, seen := distances[role]; !seen {
				distances[role] = distances[queue[0]] + 1
				queue = append(queue, role)
			}
		}
	}
	return distances, nil
}

// compile keeps the policies for the subjects in distances.
func compile(policies [][]string, distances map[string]int) []rule {
	var rules []rule
	for _, p := range policies {
		if len(p) < 3 {
			continue
		}
		distance, ok := distances[p[0]]
		if !ok {
			continue
		}
		obj, deny := strings.CutPrefix(p[1], DenyPrefix)
		base, wildcard := strings.CutSuffix(obj, "*")
		rules = append(rules, rule{base: base, wildcard: wildcard, deny: deny, act: p[2], distance: distance})
	}
	return rules
}

// Allow reports whether the rules let their visitor perform act on obj.
func (r *Rules) Allow(obj, act string) bool {
	return decide(r.own, obj, act) || decide(r.anonymous, obj, act)
}

// decide applies the rule that takes precedence among those matching obj
// and act; without one, nothing is allowed.
func decide(rules []rule, obj, act string) bool {
	var winner *rule
	for i := range rules {
		r := &rules[i]
		if (r.act == "*" || r.act == act) && r.matches(obj) && (winner == nil || r.precedes(winner)) {
			winner = r
		}
	}
	return winner != nil && !winner.deny
}

func (r *rule) matches(obj string) bool {
	if r.wildcard {
		return strings.HasPrefix(obj, r.base)
	}
	return obj == r.base
}

// precedes reports whether r takes precedence over o, when both match.
func (r *rule) precedes(o *rule) bool {
	switch {
	case len(r.base) != len(o.base):
		return len(r.base) > len(o.base)
	case r.wildcard != o.wildcard:
		return !r.wildcard
	case r.distance != o.distance:
		return r.distance < o.distance
	}
	return r.deny && !o.deny
}
