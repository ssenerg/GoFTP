package db_test

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"goftp/internal/db"
	"goftp/internal/db/dbtest"
)

// Servers starting together must not run the same migration twice.
func TestConcurrentMigrations(t *testing.T) {
	url := dbtest.Schema(t)
	ctx := context.Background()
	var pools []*pgxpool.Pool
	for range 4 {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		pools = append(pools, pool)
	}

	start := make(chan struct{})
	errs := make(chan error, len(pools))
	var wg sync.WaitGroup
	for _, pool := range pools {
		wg.Go(func() {
			<-start
			errs <- db.Migrate(ctx, pool)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Migrate(ctx, pools[0]); err != nil {
		t.Fatalf("migrating again: %v", err)
	}
	var versions, rules int
	if err := pools[0].QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := pools[0].QueryRow(ctx, "SELECT count(*) FROM casbin_rule").Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if versions != 12 || rules != 9 {
		t.Errorf("%d migrations recorded, %d rules seeded", versions, rules)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := db.Open(context.Background(), "postgres://%zz"); err == nil {
		t.Error("bad URL accepted")
	}
	if _, err := db.Open(context.Background(), "postgres://nobody@127.0.0.1:1/x?connect_timeout=1"); err == nil {
		t.Error("unreachable database accepted")
	}
}

// Admins get the actions added since the first release where their rules
// are still the default ones.
func TestActionMigrations(t *testing.T) {
	for _, m := range []struct {
		version int
		action  string
		undo    string // undoes the rest of the migration, so it can run again
	}{
		{2, "delete", "SELECT 1"},
		{3, "share", "DROP TABLE shares"},
	} {
		t.Run(m.action, func(t *testing.T) {
			pool, _ := dbtest.Open(t)
			ctx := context.Background()
			adminMay := func() bool {
				var n int
				if err := pool.QueryRow(ctx, "SELECT count(*) FROM casbin_rule WHERE ptype = 'p' AND v0 = 'admin' AND v2 = $1", m.action).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n == 1
			}
			rerun := func(sql string) {
				t.Helper()
				for _, stmt := range []string{sql, m.undo, "DELETE FROM casbin_rule WHERE v2 = '" + m.action + "'",
					"DELETE FROM schema_migrations WHERE version = " + strconv.Itoa(m.version)} {
					if _, err := pool.Exec(ctx, stmt); err != nil {
						t.Fatal(err)
					}
				}
				if err := db.Migrate(ctx, pool); err != nil {
					t.Fatal(err)
				}
			}
			if !adminMay() {
				t.Fatalf("new installs: admins may not %s", m.action)
			}
			rerun("SELECT 1")
			if !adminMay() {
				t.Errorf("default rules: admins may not %s", m.action)
			}
			rerun("DELETE FROM casbin_rule WHERE v0 = 'admin' AND v2 = 'overwrite'")
			if adminMay() {
				t.Errorf("changed rules: admins were given %s", m.action)
			}
		})
	}
}
