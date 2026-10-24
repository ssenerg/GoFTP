package config

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Dir      string         `mapstructure:"dir"`
	Addr     string         `mapstructure:"addr"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Log      LogConfig      `mapstructure:"log"`
	Server   ServerConfig   `mapstructure:"server"`
	TLS      TLSConfig      `mapstructure:"tls"`
	Limiter  LimiterConfig  `mapstructure:"limiter"`
	Upload   UploadConfig   `mapstructure:"upload"`
	Cache    CacheConfig    `mapstructure:"cache"`
	Trash    TrashConfig    `mapstructure:"trash"`
	Homes    HomesConfig    `mapstructure:"homes"`
}

type DatabaseConfig struct {
	URL string `mapstructure:"url"`
}

type AuthConfig struct {
	SessionTTL time.Duration `mapstructure:"session_ttl"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type ServerConfig struct {
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	ProxyHeader     string        `mapstructure:"proxy_header"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies"`
	MaxConnsPerIP   int           `mapstructure:"max_conns_per_ip"`
}

type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type LimiterConfig struct {
	MaxFailures int           `mapstructure:"max_failures"`
	Window      time.Duration `mapstructure:"window"`
}

type UploadConfig struct {
	MaxSize ByteSize `mapstructure:"max_size"`
	// MinFree is the free space uploads leave on the disk, for the
	// database and everything else there; 0 turns the check off.
	MinFree ByteSize `mapstructure:"min_free"`
	// ResumeWindow is how long an interrupted resumable upload keeps the
	// data it received, counted from the last that arrived.
	ResumeWindow time.Duration `mapstructure:"resume_window"`
}

// CacheConfig places the cache of image thumbnails.
type CacheConfig struct {
	// Dir defaults to goftp in the user's cache directory.
	Dir string `mapstructure:"dir"`
	// MaxSize bounds the cache; 0 disables it.
	MaxSize ByteSize `mapstructure:"max_size"`
}

// TrashConfig keeps deleted files and folders for a while, so they can be
// restored.
type TrashConfig struct {
	// Keep is how long; 0 deletes them at once, and empties the trash.
	Keep time.Duration `mapstructure:"keep"`
}

// HomesConfig gives every user a private folder of their own.
type HomesConfig struct {
	// Path is the URL path of the folder that holds them, as
	// Path/NAME; "" or "off" turns them off.
	Path string `mapstructure:"path"`
}

// ByteSize is a size in bytes; config values may use units such as "10GiB".
type ByteSize int64

var sizeUnits = map[string]float64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

func parseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(s)
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	mult, ok := sizeUnits[strings.ToLower(strings.TrimSpace(s[i:]))]
	if err != nil || !ok || n < 0 || n*mult >= math.MaxInt64 {
		return 0, fmt.Errorf("invalid size %q, e.g. \"512MiB\" or \"10GB\"", s)
	}
	return ByteSize(n * mult), nil
}

func decodeByteSize(from, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeFor[ByteSize]() || from.Kind() != reflect.String {
		return data, nil
	}
	return parseByteSize(data.(string))
}

// Flags returns the command-line flags Load understands.
func Flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("goftp", pflag.ContinueOnError)
	fs.String("config", "", "path to a config file (yaml, json or toml)")
	fs.String("dir", ".", "directory to serve")
	fs.String("addr", ":8080", "listen address")
	return fs
}

// Load builds the configuration from defaults, an optional config file,
// GOFTP_* environment variables and the parsed flags (in rising priority).
// Flags missing from fs are skipped.
func Load(fs *pflag.FlagSet) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	for _, name := range []string{"dir", "addr"} {
		if f := fs.Lookup(name); f != nil {
			if err := v.BindPFlag(name, f); err != nil {
				return nil, err
			}
		}
	}

	v.SetEnvPrefix("GOFTP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile, _ := fs.GetString("config"); configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	hooks := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		rejectUnitlessDuration,
		decodeByteSize,
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	))
	if err := v.UnmarshalExact(&cfg, hooks); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// rejectUnitlessDuration refuses bare numbers such as "timeout: 30", which
// would otherwise decode as nanoseconds.
func rejectUnitlessDuration(from, to reflect.Type, data any) (any, error) {
	if to == reflect.TypeFor[time.Duration]() && from != to && from.Kind() != reflect.String {
		return nil, fmt.Errorf("duration %v needs a unit, e.g. \"30s\"", data)
	}
	return data, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("dir", ".")
	v.SetDefault("addr", ":8080")
	v.SetDefault("database.url", "")
	v.SetDefault("auth.session_ttl", 12*time.Hour)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", time.Minute)
	v.SetDefault("server.idle_timeout", 2*time.Minute)
	v.SetDefault("server.shutdown_timeout", 10*time.Second)
	v.SetDefault("server.proxy_header", "")
	v.SetDefault("server.trusted_proxies", []string{})
	v.SetDefault("server.max_conns_per_ip", 0)
	v.SetDefault("tls.cert_file", "")
	v.SetDefault("tls.key_file", "")
	v.SetDefault("limiter.max_failures", 20)
	v.SetDefault("limiter.window", time.Minute)
	v.SetDefault("upload.max_size", 0)
	v.SetDefault("upload.min_free", 1<<30)
	v.SetDefault("upload.resume_window", 24*time.Hour)
	v.SetDefault("trash.keep", 30*24*time.Hour)
	v.SetDefault("homes.path", "/home")
	v.SetDefault("cache.dir", "")
	v.SetDefault("cache.max_size", 512<<20)
}

func (c *Config) normalize() error {
	var errs []error

	if c.Dir == "" {
		errs = append(errs, errors.New("dir must not be empty"))
	} else if abs, err := filepath.Abs(c.Dir); err != nil {
		errs = append(errs, fmt.Errorf("dir: %w", err))
	} else {
		c.Dir = abs
	}
	if c.Addr == "" {
		errs = append(errs, errors.New("addr must not be empty"))
	}
	if c.Database.URL == "" {
		errs = append(errs, errors.New("database.url is required (set GOFTP_DATABASE_URL)"))
	}
	if c.Auth.SessionTTL < time.Minute {
		errs = append(errs, errors.New("auth.session_ttl must be at least 1m"))
	}

	s := &c.Server
	if min(s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.ShutdownTimeout) <= 0 {
		errs = append(errs, errors.New("server timeouts must be positive"))
	}
	s.ProxyHeader = strings.TrimSpace(s.ProxyHeader)
	proxies := s.TrustedProxies[:0]
	for _, p := range s.TrustedProxies {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		// Fiber matches single addresses by their canonical text.
		if prefix, err := netip.ParsePrefix(p); err == nil {
			if prefix.Bits() == 0 {
				errs = append(errs, fmt.Errorf("server.trusted_proxies: %q would let every client choose its address", p))
			}
			p = prefix.Masked().String()
		} else if addr, err := netip.ParseAddr(p); err == nil {
			p = addr.WithZone("").Unmap().String()
		} else {
			errs = append(errs, fmt.Errorf("server.trusted_proxies: invalid IP or CIDR %q", p))
		}
		proxies = append(proxies, p)
	}
	s.TrustedProxies = proxies
	if s.ProxyHeader != "" && len(s.TrustedProxies) == 0 {
		errs = append(errs, errors.New("server.proxy_header requires server.trusted_proxies"))
	}
	if s.MaxConnsPerIP < 0 {
		errs = append(errs, errors.New("server.max_conns_per_ip must not be negative"))
	}

	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls.cert_file and tls.key_file must be set together"))
	}
	if c.Limiter.MaxFailures < 0 {
		errs = append(errs, errors.New("limiter.max_failures must not be negative"))
	}
	if c.Limiter.MaxFailures > 0 && c.Limiter.Window < time.Second {
		errs = append(errs, errors.New("limiter.window must be at least 1s"))
	}
	if c.Upload.MaxSize < 0 {
		errs = append(errs, errors.New("upload.max_size must not be negative"))
	}
	if c.Upload.MinFree < 0 {
		errs = append(errs, errors.New("upload.min_free must not be negative"))
	}
	if c.Upload.ResumeWindow < time.Minute {
		errs = append(errs, errors.New("upload.resume_window must be at least 1m"))
	}
	if c.Trash.Keep < 0 {
		errs = append(errs, errors.New("trash.keep must not be negative"))
	}
	if h := strings.TrimSpace(c.Homes.Path); h == "" || h == "off" {
		c.Homes.Path = ""
	} else {
		clean := path.Clean("/" + strings.Trim(h, "/"))
		if !strings.HasPrefix(h, "/") || clean == "/" || strings.Contains(clean, "/.") || strings.ContainsAny(clean, "*\\") {
			errs = append(errs, errors.New(`homes.path must be a folder's URL path such as "/home", not "/" or a dot folder`))
		}
		c.Homes.Path = clean
	}
	if c.Cache.MaxSize < 0 {
		errs = append(errs, errors.New("cache.max_size must not be negative"))
	}
	if c.Cache.Dir != "" && c.Cache.MaxSize > 0 {
		if abs, err := filepath.Abs(c.Cache.Dir); err != nil {
			errs = append(errs, fmt.Errorf("cache.dir: %w", err))
		} else if c.Cache.Dir = abs; servedFrom(c.Dir, abs) {
			// Anyone who may read there would get thumbnails of every image.
			errs = append(errs, errors.New("cache.dir must be outside dir, or in a folder of it whose name starts with a dot"))
		}
	}
	return errors.Join(errs...)
}

// servedFrom reports whether the path p is in dir and would be served from
// it: no part of it relative to dir starts with a dot (as ".." does).
func servedFrom(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	for part := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
		if part != "." && strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}
