package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// PgStore is the Postgres Store.
type PgStore struct{ db *pgxpool.Pool }

func NewPgStore(db *pgxpool.Pool) *PgStore { return &PgStore{db: db} }

const userColumns = "id, username, password_hash, must_change_password, created_at, home_quota"

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.CreatedAt, &u.HomeQuota)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *PgStore) CreateUser(ctx context.Context, username, passwordHash string) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx,
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
		username, passwordHash).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return 0, ErrExists
	}
	return id, err
}

func (s *PgStore) UserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE username = $1", username))
}

func (s *PgStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.Query(ctx, "SELECT "+userColumns+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (User, error) {
		u, err := scanUser(row)
		if err != nil {
			return User{}, err
		}
		return *u, nil
	})
}

func (s *PgStore) SetPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			"UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = now() WHERE id = $1",
			userID, passwordHash, mustChange)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "DELETE FROM app_passwords WHERE user_id = $1", userID); err != nil || !mustChange {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM shares WHERE created_by = $1", userID)
		return err
	})
}

func (s *PgStore) CreateAppPassword(ctx context.Context, tokenHash []byte, ap *AppPassword) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The row lock serializes a user's app passwords, so they cannot
		// exceed the limit together.
		var id int64
		err := tx.QueryRow(ctx, "SELECT id FROM users WHERE id = $1 FOR UPDATE", ap.UserID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM app_passwords WHERE user_id = $1", id).Scan(&n); err != nil {
			return err
		}
		if n >= MaxAppPasswords {
			return ErrTooMany
		}
		return tx.QueryRow(ctx, "INSERT INTO app_passwords (user_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id, created_at",
			id, ap.Name, tokenHash).Scan(&ap.ID, &ap.CreatedAt)
	})
}

func (s *PgStore) AppPasswords(ctx context.Context, userID int64) ([]AppPassword, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, name, created_at, last_used_at FROM app_passwords
		WHERE user_id = $1 ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AppPassword, error) {
		var (
			ap       AppPassword
			lastUsed *time.Time
		)
		err := row.Scan(&ap.ID, &ap.UserID, &ap.Name, &ap.CreatedAt, &lastUsed)
		if lastUsed != nil {
			ap.LastUsedAt = *lastUsed
		}
		return ap, err
	})
}

func (s *PgStore) DeleteAppPassword(ctx context.Context, userID, id int64) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM app_passwords WHERE id = $1 AND user_id = $2", id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

func (s *PgStore) AppPasswordUser(ctx context.Context, username string, tokenHash []byte) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT u.id, u.username, u.password_hash, u.must_change_password, u.created_at, u.home_quota
		FROM app_passwords a JOIN users u ON u.id = a.user_id
		WHERE a.token_hash = $1 AND u.username = $2`, tokenHash, username))
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(ctx, `UPDATE app_passwords SET last_used_at = now()
		WHERE token_hash = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, tokenHash)
	return u, err
}

func (s *PgStore) SetHomeQuota(ctx context.Context, userID int64, quota *int64) error {
	tag, err := s.db.Exec(ctx, "UPDATE users SET home_quota = $2 WHERE id = $1", userID, quota)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

func (s *PgStore) DeleteUser(ctx context.Context, userID int64) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// maxUserSessions bounds the sessions a single user can pile up.
const maxUserSessions = 100

func (s *PgStore) CreateSession(ctx context.Context, tokenHash []byte, u *User, expires time.Time) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The row lock orders this against SetPassword: either its update
		// comes first and the hash no longer matches, or its deletion of
		// the user's sessions sees this one.
		tag, err := tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at)
			SELECT $1, id, $3 FROM users WHERE id = $2 AND password_hash = $4 FOR SHARE`,
			tokenHash, u.ID, expires, u.PasswordHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash IN (
			SELECT token_hash FROM sessions WHERE user_id = $1 ORDER BY created_at DESC OFFSET $2)`,
			u.ID, maxUserSessions)
		return err
	})
}

func (s *PgStore) SessionUser(ctx context.Context, tokenHash []byte) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT u.id, u.username, u.password_hash, u.must_change_password, u.created_at, u.home_quota
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash))
}

func (s *PgStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE token_hash = $1", tokenHash)
	return err
}

func (s *PgStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE expires_at <= now()")
	return err
}

const shareColumns = "s.id, s.path, s.is_dir, s.password_hash, s.upload, s.max_uses, s.uses, s.max_bytes, s.bytes, " +
	"s.created_by, u.username, s.created_at, s.expires_at, s.last_used_at"

func scanShare(row pgx.Row) (*Share, error) {
	var (
		sh       Share
		lastUsed *time.Time
	)
	err := row.Scan(&sh.ID, &sh.Path, &sh.IsDir, &sh.PasswordHash, &sh.Upload, &sh.MaxUses, &sh.Uses, &sh.MaxBytes, &sh.Bytes,
		&sh.CreatedBy, &sh.Creator, &sh.CreatedAt, &sh.ExpiresAt, &lastUsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if lastUsed != nil {
		sh.LastUsedAt = *lastUsed
	}
	return &sh, err
}

func (s *PgStore) CreateShare(ctx context.Context, tokenHash []byte, sh *Share) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The row lock serializes a user's links, so they cannot exceed
		// the limit together.
		var id int64
		err := tx.QueryRow(ctx, "SELECT id FROM users WHERE id = $1 FOR UPDATE", sh.CreatedBy).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM shares WHERE created_by = $1 AND expires_at > now()", id).Scan(&n); err != nil {
			return err
		}
		if n >= MaxShares {
			return ErrTooMany
		}
		return tx.QueryRow(ctx, `INSERT INTO shares (token_hash, path, is_dir, created_by, password_hash, expires_at, upload, max_uses, max_bytes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, created_at`,
			tokenHash, sh.Path, sh.IsDir, id, sh.PasswordHash, sh.ExpiresAt, sh.Upload, sh.MaxUses, sh.MaxBytes).Scan(&sh.ID, &sh.CreatedAt)
	})
}

func (s *PgStore) ShareByToken(ctx context.Context, tokenHash []byte) (*Share, error) {
	return scanShare(s.db.QueryRow(ctx, "SELECT "+shareColumns+` FROM shares s JOIN users u ON u.id = s.created_by
		WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash))
}

func (s *PgStore) ShareByID(ctx context.Context, id int64) (*Share, error) {
	return scanShare(s.db.QueryRow(ctx, "SELECT "+shareColumns+` FROM shares s JOIN users u ON u.id = s.created_by
		WHERE s.id = $1 AND s.expires_at > now()`, id))
}

func (s *PgStore) UseShare(ctx context.Context, id int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE shares SET uses = uses + 1, last_used_at = now()
		WHERE id = $1 AND expires_at > now() AND (max_uses = 0 OR uses < max_uses)`, id)
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *PgStore) AddShareBytes(ctx context.Context, id, n int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE shares SET bytes = bytes + $2
		WHERE id = $1 AND expires_at > now() AND (max_bytes = 0 OR bytes + $2 <= max_bytes)`, id, n)
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *PgStore) SubShareBytes(ctx context.Context, id, n int64) error {
	_, err := s.db.Exec(ctx, "UPDATE shares SET bytes = greatest(bytes - $2, 0) WHERE id = $1", id, n)
	return err
}

func (s *PgStore) UnuseShare(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, "UPDATE shares SET uses = uses - 1 WHERE id = $1 AND uses > 0", id)
	return err
}

func (s *PgStore) TouchShare(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `UPDATE shares SET last_used_at = now()
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id)
	return err
}

func (s *PgStore) Shares(ctx context.Context, userID int64) ([]Share, error) {
	rows, err := s.db.Query(ctx, "SELECT "+shareColumns+` FROM shares s JOIN users u ON u.id = s.created_by
		WHERE s.expires_at > now() AND ($1::bigint = 0 OR s.created_by = $1) ORDER BY s.created_at DESC, s.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Share, error) {
		sh, err := scanShare(row)
		if err != nil {
			return Share{}, err
		}
		return *sh, nil
	})
}

func (s *PgStore) DeleteShare(ctx context.Context, id, userID int64) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM shares WHERE id = $1 AND ($2::bigint = 0 OR created_by = $2)", id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

func (s *PgStore) DeleteExpiredShares(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM shares WHERE expires_at <= now()")
	return err
}

const uploadColumns = "id, user_id, dir, name, length, replace, temp, share_id, created_at, expires_at"

func scanUpload(row pgx.Row) (*Upload, error) {
	var up Upload
	err := row.Scan(&up.ID, &up.UserID, &up.Dir, &up.Name, &up.Length, &up.Replace, &up.Temp, &up.ShareID, &up.CreatedAt, &up.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &up, err
}

func (s *PgStore) CreateUpload(ctx context.Context, tokenHash []byte, up *Upload, keep time.Duration) error {
	return s.db.QueryRow(ctx, `INSERT INTO uploads (token_hash, user_id, dir, name, length, replace, temp, share_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + $9::interval) RETURNING id, created_at, expires_at`,
		tokenHash, up.UserID, up.Dir, up.Name, up.Length, up.Replace, up.Temp, up.ShareID, keep).Scan(&up.ID, &up.CreatedAt, &up.ExpiresAt)
}

func (s *PgStore) UploadByToken(ctx context.Context, tokenHash []byte) (*Upload, error) {
	return scanUpload(s.db.QueryRow(ctx, "SELECT "+uploadColumns+" FROM uploads WHERE token_hash = $1 AND expires_at > now()", tokenHash))
}

func (s *PgStore) ClaimUpload(ctx context.Context, id int64, writer string, lease time.Duration) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE uploads SET writer = $2, writer_until = now() + $3::interval
		WHERE id = $1 AND expires_at > now() AND (writer = '' OR writer_until <= now())`, id, writer, lease)
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *PgStore) ExtendUpload(ctx context.Context, id int64, writer string, lease, keep time.Duration) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE uploads SET writer_until = now() + $3::interval, expires_at = now() + $4::interval
		WHERE id = $1 AND writer = $2`, id, writer, lease, keep)
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *PgStore) ReleaseUpload(ctx context.Context, id int64, writer string, keep time.Duration) error {
	_, err := s.db.Exec(ctx, `UPDATE uploads SET writer = '', writer_until = '-infinity', expires_at = now() + $3::interval
		WHERE id = $1 AND writer = $2`, id, writer, keep)
	return err
}

func (s *PgStore) DeleteUpload(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, "DELETE FROM uploads WHERE id = $1", id)
	return err
}

func (s *PgStore) TakeExpiredUploads(ctx context.Context, limit int) ([]Upload, error) {
	rows, err := s.db.Query(ctx, `DELETE FROM uploads WHERE id IN (
			SELECT id FROM uploads WHERE expires_at <= now() AND writer_until <= now()
			ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING `+uploadColumns, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Upload, error) {
		up, err := scanUpload(row)
		if err != nil {
			return Upload{}, err
		}
		return *up, nil
	})
}

// policyChannel is notified on every policy change so that running servers
// reload their enforcer.
const policyChannel = "goftp_policy"

// PgAdapter stores Casbin rules in the casbin_rule table.
type PgAdapter struct{ db *pgxpool.Pool }

var (
	_ persist.BatchAdapter     = (*PgAdapter)(nil)
	_ persist.UpdatableAdapter = (*PgAdapter)(nil)
)

func NewPgAdapter(db *pgxpool.Pool) *PgAdapter { return &PgAdapter{db: db} }

const ruleFields = 6

func (a *PgAdapter) LoadPolicy(m model.Model) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := a.db.Query(ctx, "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rule [ruleFields + 1]string
		if err := rows.Scan(&rule[0], &rule[1], &rule[2], &rule[3], &rule[4], &rule[5], &rule[6]); err != nil {
			return err
		}
		if err := persist.LoadPolicyArray(trimRule(rule[:]), m); err != nil {
			return err
		}
	}
	return rows.Err()
}

// trimRule drops the empty trailing fields of a stored rule.
func trimRule(rule []string) []string {
	n := len(rule)
	for n > 1 && rule[n-1] == "" {
		n--
	}
	return rule[:n]
}

// write runs fn in a transaction that notifies servers of the change.
func (a *PgAdapter) write(fn func(ctx context.Context, tx pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "SELECT pg_notify($1, '')", policyChannel)
		return err
	})
}

func (a *PgAdapter) SavePolicy(m model.Model) error {
	return a.write(func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM casbin_rule"); err != nil {
			return err
		}
		for _, sec := range []string{"p", "g"} {
			for ptype, ast := range m[sec] {
				for _, rule := range ast.Policy {
					if err := insertRule(ctx, tx, ptype, rule); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (a *PgAdapter) AddPolicy(sec, ptype string, rule []string) error {
	return a.AddPolicies(sec, ptype, [][]string{rule})
}

func (a *PgAdapter) AddPolicies(_, ptype string, rules [][]string) error {
	return a.write(func(ctx context.Context, tx pgx.Tx) error {
		for _, rule := range rules {
			if err := insertRule(ctx, tx, ptype, rule); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *PgAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	return a.RemovePolicies(sec, ptype, [][]string{rule})
}

func (a *PgAdapter) RemovePolicies(_, ptype string, rules [][]string) error {
	return a.write(func(ctx context.Context, tx pgx.Tx) error {
		for _, rule := range rules {
			if err := deleteRule(ctx, tx, ptype, rule); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *PgAdapter) RemoveFilteredPolicy(_, ptype string, fieldIndex int, fieldValues ...string) error {
	where, args, err := ruleFilter(ptype, fieldIndex, fieldValues)
	if err != nil {
		return err
	}
	return a.write(func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM casbin_rule WHERE "+where, args...)
		return err
	})
}

func (a *PgAdapter) UpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newRule})
}

func (a *PgAdapter) UpdatePolicies(_, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("casbin: old and new rules differ in number")
	}
	return a.write(func(ctx context.Context, tx pgx.Tx) error {
		for i := range oldRules {
			if err := deleteRule(ctx, tx, ptype, oldRules[i]); err != nil {
				return err
			}
			if err := insertRule(ctx, tx, ptype, newRules[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *PgAdapter) UpdateFilteredPolicies(_, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	where, args, err := ruleFilter(ptype, fieldIndex, fieldValues)
	if err != nil {
		return nil, err
	}
	var old [][]string
	err = a.write(func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "DELETE FROM casbin_rule WHERE "+where+" RETURNING v0, v1, v2, v3, v4, v5", args...)
		if err != nil {
			return err
		}
		old, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) ([]string, error) {
			var rule [ruleFields]string
			err := row.Scan(&rule[0], &rule[1], &rule[2], &rule[3], &rule[4], &rule[5])
			return trimRule(rule[:]), err
		})
		if err != nil {
			return err
		}
		for _, rule := range newRules {
			if err := insertRule(ctx, tx, ptype, rule); err != nil {
				return err
			}
		}
		return nil
	})
	return old, err
}

// ruleFilter builds the WHERE clause selecting rules of ptype whose fields
// from fieldIndex on equal fieldValues; empty values match anything.
func ruleFilter(ptype string, fieldIndex int, fieldValues []string) (string, []any, error) {
	if fieldIndex < 0 || fieldIndex+len(fieldValues) > ruleFields {
		return "", nil, fmt.Errorf("casbin: invalid filter at field %d", fieldIndex)
	}
	where := "ptype = $1"
	args := []any{ptype}
	for i, v := range fieldValues {
		if v != "" {
			args = append(args, v)
			where += fmt.Sprintf(" AND v%d = $%d", fieldIndex+i, len(args))
		}
	}
	return where, args, nil
}

func padRule(ptype string, rule []string) ([]any, error) {
	if len(rule) > ruleFields {
		return nil, fmt.Errorf("casbin: rule has more than %d fields", ruleFields)
	}
	values := []any{ptype, "", "", "", "", "", ""}
	for i, v := range rule {
		values[i+1] = v
	}
	return values, nil
}

func insertRule(ctx context.Context, tx pgx.Tx, ptype string, rule []string) error {
	values, err := padRule(ptype, rule)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, values...)
	return err
}

func deleteRule(ctx context.Context, tx pgx.Tx, ptype string, rule []string) error {
	values, err := padRule(ptype, rule)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM casbin_rule WHERE ptype = $1
		AND v0 = $2 AND v1 = $3 AND v2 = $4 AND v3 = $5 AND v4 = $6 AND v5 = $7`, values...)
	return err
}

// WatchPolicies reloads the enforcer whenever the policy changes, and every
// few minutes in case a notification was missed. It returns when ctx ends.
func WatchPolicies(ctx context.Context, db *pgxpool.Pool, e *casbin.SyncedEnforcer, log *zap.Logger) {
	const resync = 5 * time.Minute
	reload := func() {
		if err := e.LoadPolicy(); err != nil {
			log.Error("reload policy", zap.Error(err))
		}
	}
	for ctx.Err() == nil {
		err := listen(ctx, db, resync, reload)
		if ctx.Err() == nil {
			log.Warn("policy listener stopped, retrying", zap.Error(err))
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func listen(ctx context.Context, db *pgxpool.Pool, resync time.Duration, reload func()) error {
	pooled, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	// A connection left in LISTEN mode must not go back to the pool.
	conn := pooled.Hijack()
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{policyChannel}.Sanitize()); err != nil {
		return err
	}
	// Changes made before LISTEN took effect were not notified.
	reload()
	for {
		wait, cancel := context.WithTimeout(ctx, resync)
		_, err := conn.WaitForNotification(wait)
		cancel()
		switch {
		case err == nil, errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			reload()
		case ctx.Err() != nil:
			return nil
		default:
			return err
		}
	}
}

// NewPgEnforcer loads the policy from Postgres.
func NewPgEnforcer(db *pgxpool.Pool) (*casbin.SyncedEnforcer, error) {
	e, err := NewEnforcer(NewPgAdapter(db))
	if err != nil && strings.Contains(err.Error(), "casbin_rule") {
		return nil, fmt.Errorf("load policy (run migrations first): %w", err)
	}
	return e, err
}
