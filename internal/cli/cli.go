// Package cli implements the goftp command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"goftp/internal/auth"
	"goftp/internal/config"
	"goftp/internal/db"
	"goftp/internal/logger"
	"goftp/internal/server"
)

// Execute runs the command line with args.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	root := newRoot()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.ExecuteContext(ctx)
}

func newRoot() *cobra.Command {
	serve := serveCmd()
	root := &cobra.Command{
		Use:   "goftp",
		Short: "A resumable file server with users and roles",
		Long: "goftp serves a directory over HTTP with resumable downloads and uploads.\n" +
			"Users sign in; Casbin policies stored in Postgres decide what they may do.\n" +
			"Without a command, goftp serves.",
		Args:          cobra.NoArgs,
		RunE:          serve.RunE,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("config", "", "path to a config file (yaml, json or toml)")
	root.Flags().AddFlagSet(serve.Flags())
	root.AddCommand(serve, migrateCmd(), userCmd(), policyCmd())
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve files (the default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cmd.Flags())
			if err != nil {
				return err
			}
			return serve(cmd.Context(), cfg)
		},
	}
	cmd.Flags().String("dir", ".", "directory to serve")
	cmd.Flags().String("addr", ":8080", "listen address")
	return cmd
}

func serve(ctx context.Context, cfg *config.Config) error {
	log, err := logger.New(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A second signal during the graceful shutdown ends the process.
	context.AfterFunc(ctx, stop)

	pool, err := db.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer pool.Close()
	enforcer, err := auth.NewPgEnforcer(pool)
	if err != nil {
		return err
	}
	svc := auth.NewService(auth.NewPgStore(pool), enforcer, cfg.Auth.SessionTTL)

	// srv is not closed: after a timed-out shutdown, requests may still be
	// running until the process exits.
	srv, err := server.New(cfg, log, svc)
	if err != nil {
		return fmt.Errorf("serve %s: %w", cfg.Dir, err)
	}

	background, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { auth.WatchPolicies(background, pool, enforcer, log) })
	wg.Go(func() { svc.PurgeExpired(background, time.Hour, log) })
	defer func() {
		cancel()
		wg.Wait()
	}()

	if err := srv.Listen(ctx); err != nil {
		return err
	}
	log.Info("server stopped")
	return nil
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Create or upgrade the database schema",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pool, err := openDB(cmd)
			if err != nil {
				return err
			}
			pool.Close()
			cmd.Println("database schema is up to date")
			return nil
		},
	}
}

// openDB connects to the configured database and migrates it.
func openDB(cmd *cobra.Command) (*pgxpool.Pool, error) {
	cfg, err := config.Load(cmd.Flags())
	if err != nil {
		return nil, err
	}
	return db.Open(cmd.Context(), cfg.Database.URL)
}

// withService runs fn with a service backed by the configured database.
func withService(cmd *cobra.Command, fn func(*auth.Service) error) error {
	return withConfig(cmd, func(_ *config.Config, svc *auth.Service) error { return fn(svc) })
}

// withConfig is withService for commands that need the configuration too.
func withConfig(cmd *cobra.Command, fn func(*config.Config, *auth.Service) error) error {
	cfg, err := config.Load(cmd.Flags())
	if err != nil {
		return err
	}
	pool, err := db.Open(cmd.Context(), cfg.Database.URL)
	if err != nil {
		return err
	}
	defer pool.Close()
	enforcer, err := auth.NewPgEnforcer(pool)
	if err != nil {
		return err
	}
	return fn(cfg, auth.NewService(auth.NewPgStore(pool), enforcer, cfg.Auth.SessionTTL))
}

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
		Args:  cobra.NoArgs,
		RunE:  help,
	}
	roles := strings.Join(auth.Roles, ", ")

	add := &cobra.Command{
		Use:   "add NAME",
		Short: "Sign up a user; prints a temporary password",
		Long: "Sign up a user with a role (" + roles + ").\n" +
			"The printed temporary password has to be changed at the first login.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")
			return withService(cmd, func(svc *auth.Service) error {
				password, err := svc.CreateUser(cmd.Context(), args[0], role)
				if err != nil {
					return err
				}
				printPassword(cmd, fmt.Sprintf("created user %s with role %s", auth.NormalizeUsername(args[0]), role), password)
				return nil
			})
		},
	}
	add.Flags().String("role", "user", "role: "+roles)

	list := &cobra.Command{
		Use:   "list",
		Short: "List users and their roles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				users, err := svc.Users(cmd.Context())
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "USERNAME\tROLE\tPASSWORD\tHOME QUOTA\tCREATED")
				for _, u := range users {
					state := "set"
					if u.MustChangePassword {
						state = "temporary"
					}
					quota := "default"
					if q := u.HomeQuota; q != nil {
						quota = "none"
						if *q > 0 {
							quota = config.ByteSize(*q).String()
						}
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", u.Username, orNone(u.Role), state, quota, u.CreatedAt.Format(time.DateTime))
				}
				return w.Flush()
			})
		},
	}

	passwd := &cobra.Command{
		Use:   "passwd NAME",
		Short: "Reset a password; prints a temporary one and ends the user's sessions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				password, err := svc.ResetPassword(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				printPassword(cmd, "reset the password of "+auth.NormalizeUsername(args[0]), password)
				return nil
			})
		},
	}

	twoFactorOff := &cobra.Command{
		Use:   "two-factor-off NAME",
		Short: "Turn off two-factor sign-in for a user who lost their app and recovery codes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				on, err := svc.ResetTwoFactor(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				name := auth.NormalizeUsername(args[0])
				if !on {
					cmd.Printf("two-factor sign-in was off for %s already\n", name)
					return nil
				}
				cmd.Printf("turned off two-factor sign-in for %s: their password alone signs them in\n", name)
				return nil
			})
		},
	}

	role := &cobra.Command{
		Use:   "role NAME ROLE",
		Short: "Change a user's role (" + roles + ")",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				if err := svc.SetRole(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				cmd.Printf("%s now has role %s\n", auth.NormalizeUsername(args[0]), args[1])
				return nil
			})
		},
	}

	quota := &cobra.Command{
		Use:   "quota NAME SIZE",
		Short: "Set how much a user's home may hold: a size such as 10GiB, none for no limit, or default for homes.quota",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := config.ParseQuota(args[1])
			if err != nil {
				return err
			}
			return withService(cmd, func(svc *auth.Service) error {
				if err := svc.SetHomeQuota(cmd.Context(), args[0], q); err != nil {
					return err
				}
				name := auth.NormalizeUsername(args[0])
				switch {
				case q == nil:
					cmd.Printf("the home of %s may hold as much as homes.quota says\n", name)
				case *q == 0:
					cmd.Printf("the home of %s may hold any amount\n", name)
				default:
					cmd.Printf("the home of %s may hold %s\n", name, config.ByteSize(*q))
				}
				return nil
			})
		},
	}

	del := &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a user, their policies and sessions; their home goes to the trash (with the trash off, it is deleted)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withConfig(cmd, func(cfg *config.Config, svc *auth.Service) error {
				name := auth.NormalizeUsername(args[0])
				if err := svc.DeleteUser(cmd.Context(), name); err != nil {
					return err
				}
				cmd.Printf("deleted user %s\n", name)
				// The server moves it there anyway once a user of that
				// name shows up.
				switch moved, err := server.TrashHome(cfg, "goftp user delete", name); {
				case err != nil:
					cmd.PrintErrf("their home stays private, but could not be moved to the trash: %v\n", err)
				case moved && cfg.Trash.Keep == 0:
					cmd.Printf("deleted their home, as the trash is off\n")
				case moved:
					cmd.Printf("moved their home to the trash\n")
				}
				return nil
			})
		},
	}

	cmd.AddCommand(add, list, passwd, twoFactorOff, role, quota, del)
	return cmd
}

// help is the action of command groups; with Args set, cobra reports
// unknown subcommands as errors instead of printing help.
func help(cmd *cobra.Command, _ []string) error { return cmd.Help() }

func printPassword(cmd *cobra.Command, done, password string) {
	cmd.Println(done)
	cmd.Println("temporary password:", password)
	cmd.Println("it has to be changed at the first login")
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage access rules",
		Long: "Access rules allow a subject to perform an action on URL paths.\n\n" +
			"Subjects: a role (" + strings.Join(auth.Roles, ", ") + "), " + auth.Anonymous + " or user:NAME.\n" +
			"Actions:  " + auth.ActRead + " (list, download), " + auth.ActWrite + " (upload new files, create folders), " +
			auth.ActOverwrite + " (replace files), " + auth.ActDelete + " (delete, rename),\n" +
			"          " + auth.ActShare + " (create links for people without an account) or *.\n" +
			"Paths:    \"/docs/*\" covers /docs/ and everything below it; \"/docs/\" is just the listing.\n" +
			"          A path starting with \"!\" denies, as in a .gitignore: \"!/docs/private/*\".\n\n" +
			"Roles inherit the rules of the roles below them: " + strings.Join(auth.Roles, " > ") + ".\n" +
			"The rule for the longest path decides; for the same path, a user's own rules come\n" +
			"before their roles', a role's before those it inherits, and denials before the rest.",
		Args: cobra.NoArgs,
		RunE: help,
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the rules and role assignments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				perms, roles, err := svc.Policies()
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "SUBJECT\tPATH\tACTION")
				for _, p := range perms {
					fmt.Fprintln(w, strings.Join(p, "\t"))
				}
				fmt.Fprintln(w, "\nSUBJECT\tINHERITS FROM")
				for _, g := range roles {
					fmt.Fprintln(w, strings.Join(g, "\t"))
				}
				return w.Flush()
			})
		},
	}

	add := &cobra.Command{
		Use:   "add SUBJECT PATH ACTION",
		Short: "Allow SUBJECT to perform ACTION on PATH, or deny it with !PATH",
		Example: "  goftp policy add anonymous '/public/*' read\n  goftp policy add user:alice '/alice/*' '*'\n" +
			"  goftp policy add user '!/hr/*' '*'           # users may not open /hr/\n" +
			"  goftp policy add admin '/hr/*' '*'           # but admins may",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				added, err := svc.AddPolicy(args[0], args[1], args[2])
				if err != nil {
					return err
				}
				if !added {
					return errors.New("the rule already exists")
				}
				cmd.Println("rule added")
				return nil
			})
		},
	}

	remove := &cobra.Command{
		Use:   "remove SUBJECT PATH ACTION",
		Short: "Remove a rule",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd, func(svc *auth.Service) error {
				removed, err := svc.RemovePolicy(args[0], args[1], args[2])
				if err != nil {
					return err
				}
				if !removed {
					return errors.New("no such rule")
				}
				cmd.Println("rule removed")
				return nil
			})
		},
	}

	cmd.AddCommand(list, add, remove)
	return cmd
}
