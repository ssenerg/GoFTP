package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrTooMany  = errors.New("too many")
	ErrInvalid  = errors.New("invalid")
)

type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	MustChangePassword bool
	CreatedAt          time.Time
	// HomeQuota is how much their home may hold, in bytes: nil for the
	// server's default, 0 for no limit.
	HomeQuota *int64
	// TwoFactor is set when they sign in with a code too (see
	// LoginWithCode).
	TwoFactor bool
}

// TwoFactor is what is stored of a user's two-factor sign-in.
type TwoFactor struct {
	Secret        []byte // nil while it is off
	Pending       []byte // a secret being set up, until a code of it comes; nil if none
	Step          int64  // the last time step a code was used for
	RecoveryCodes int    // how many are left
}

// Share is a link that lets people without an account read a file or
// folder until it expires, or upload into a folder.
type Share struct {
	ID           int64
	Path         string // URL path of the shared file or folder
	IsDir        bool
	PasswordHash string // empty when the link needs no password
	// Upload is set for links to upload into the folder, which do not let
	// people read it.
	Upload  bool
	MaxUses int // downloads, or files uploaded, it allows; 0 for no limit
	Uses    int
	// MaxBytes is how much may be sent through an upload link, 0 for no
	// limit; Bytes how much was, or is being.
	MaxBytes  int64
	Bytes     int64
	CreatedBy int64
	Creator   string // the username of CreatedBy
	CreatedAt time.Time
	ExpiresAt time.Time
	// LastUsedAt is when it was last opened or used; zero if never.
	LastUsedAt time.Time
}

// UsedUp reports whether the link was used as often as it may be.
func (sh *Share) UsedUp() bool { return sh.MaxUses > 0 && sh.Uses >= sh.MaxUses }

// Upload is an unfinished resumable upload: Length bytes for the file Name
// in the folder Dir, of which the hidden file Temp next to it holds what
// arrived so far.
type Upload struct {
	ID        int64
	UserID    int64  // the uploader, 0 for anonymous visitors
	Dir       string // URL path of the folder
	Name      string
	Length    int64
	Replace   bool // may replace a file of that name
	Temp      string
	ShareID   int64     // the upload link it came through, if any
	Mtime     time.Time // the modification time the file gets; zero for when it is stored
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store persists users, sessions, share links and unfinished uploads.
// Sessions, links and uploads are keyed by the SHA-256 hash of their token.
type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string) (int64, error)
	UserByName(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	// SetPassword also ends all of the user's sessions and app passwords
	// and, for a temporary password (mustChange), their share links.
	SetPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error
	// DeleteUser also deletes the user's sessions, app passwords and share
	// links.
	DeleteUser(ctx context.Context, userID int64) error
	// SetHomeQuota sets how much the user's home may hold (see
	// User.HomeQuota).
	SetHomeQuota(ctx context.Context, userID int64, quota *int64) error

	// CreateAppPassword stores the app password ap of ap.UserID by the
	// hash of the password, and sets its ID and CreatedAt; ErrTooMany if
	// the user has MaxAppPasswords already, ErrNotFound if there is no
	// such user.
	CreateAppPassword(ctx context.Context, tokenHash []byte, ap *AppPassword) error
	// AppPasswords lists the app passwords of userID, newest first.
	AppPasswords(ctx context.Context, userID int64) ([]AppPassword, error)
	// DeleteAppPassword deletes the app password id of userID.
	DeleteAppPassword(ctx context.Context, userID, id int64) error
	// AppPasswordUser returns the user username, if tokenHash is the hash
	// of one of their app passwords, and notes it was used now; at most
	// once a minute.
	AppPasswordUser(ctx context.Context, username string, tokenHash []byte) (*User, error)

	// ShareFolder stores fs, or changes how and until when the folder of fs
	// is shared with its user if it is already, and sets ID and CreatedAt;
	// ErrTooMany if the owner has MaxFolderShares that have not expired.
	ShareFolder(ctx context.Context, fs *FolderShare) error
	// FolderShares lists the unexpired folder shares of ownerID, of
	// everyone for 0, newest first.
	FolderShares(ctx context.Context, ownerID int64) ([]FolderShare, error)
	// SharedWith lists the folders shared with userID that have not
	// expired.
	SharedWith(ctx context.Context, userID int64) ([]FolderShare, error)
	// DeleteFolderShare deletes the folder share id, if userID (unless 0)
	// is its owner or its user, and returns it, without the usernames
	// (ErrNotFound if there is no such share).
	DeleteFolderShare(ctx context.Context, id, userID int64) (*FolderShare, error)
	// MoveFolderShare gives the folder share id the path p, where its
	// folder moved, and deletes a share of p with the same user, which a
	// folder that is gone left (ErrNotFound if there is no share id).
	MoveFolderShare(ctx context.Context, id int64, p string) error

	// TwoFactor returns what is stored of userID's two-factor sign-in
	// (ErrNotFound if there is no such user).
	TwoFactor(ctx context.Context, userID int64) (*TwoFactor, error)
	// SetTwoFactorPending keeps secret for userID until a code of it comes.
	SetTwoFactorPending(ctx context.Context, userID int64, secret []byte) error
	// EnableTwoFactor turns two-factor sign-in on for userID with secret,
	// if it is still pending (ErrNotFound otherwise), noting step as used,
	// with the recovery codes of hashes; all of the user's sessions end.
	EnableTwoFactor(ctx context.Context, userID int64, secret []byte, step int64, hashes [][]byte) error
	// DisableTwoFactor turns it off, and deletes the recovery codes.
	DisableTwoFactor(ctx context.Context, userID int64) error
	// UseTwoFactorStep notes that a code of step was used, and reports
	// whether none of it or of a later step had been.
	UseTwoFactorStep(ctx context.Context, userID, step int64) (bool, error)
	// UseRecoveryCode deletes the recovery code of hash, and reports
	// whether userID had it.
	UseRecoveryCode(ctx context.Context, userID int64, hash []byte) (bool, error)
	// SetRecoveryCodes replaces userID's recovery codes with those of
	// hashes.
	SetRecoveryCodes(ctx context.Context, userID int64, hashes [][]byte) error

	// CreateSession starts a session for u, unless u was deleted or changed
	// password since it was read (ErrNotFound). It may drop the user's
	// oldest sessions to bound their number.
	CreateSession(ctx context.Context, tokenHash []byte, u *User, expires time.Time) error
	// SessionUser returns the user of an unexpired session.
	SessionUser(ctx context.Context, tokenHash []byte) (*User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	DeleteExpiredSessions(ctx context.Context) error

	// CreateShare stores sh and sets its ID and CreatedAt, unless its
	// creator was deleted (ErrNotFound) or has MaxShares unexpired links
	// already (ErrTooMany).
	CreateShare(ctx context.Context, tokenHash []byte, sh *Share) error
	// ShareByToken returns an unexpired share link.
	ShareByToken(ctx context.Context, tokenHash []byte) (*Share, error)
	// ShareByID returns the unexpired share link id.
	ShareByID(ctx context.Context, id int64) (*Share, error)
	// UseShare counts a use of the unexpired link id and notes when it
	// was, unless it was used as often as it may be (false).
	UseShare(ctx context.Context, id int64) (bool, error)
	// UnuseShare takes back a use of the link id, counted for a file that
	// was not stored after all.
	UnuseShare(ctx context.Context, id int64) error
	// AddShareBytes counts n more bytes sent through the unexpired upload
	// link id, unless that would go past its MaxBytes (false).
	AddShareBytes(ctx context.Context, id, n int64) (bool, error)
	// SubShareBytes takes back n bytes counted for the link id.
	SubShareBytes(ctx context.Context, id, n int64) error
	// TouchShare notes that the link id was opened now. It may skip
	// noting it if it was within the last minute.
	TouchShare(ctx context.Context, id int64) error
	// Shares lists the unexpired links created by userID, or by anyone if
	// userID is 0, newest first.
	Shares(ctx context.Context, userID int64) ([]Share, error)
	// DeleteShare deletes the link id if userID created it, or whoever did
	// if userID is 0.
	DeleteShare(ctx context.Context, id, userID int64) error
	// DeleteExpiredShares deletes the links and folder shares that
	// expired.
	DeleteExpiredShares(ctx context.Context) error

	// CreateUpload stores up, which expires after keep, and sets its ID,
	// CreatedAt and ExpiresAt.
	CreateUpload(ctx context.Context, tokenHash []byte, up *Upload, keep time.Duration) error
	// UploadByToken returns an unexpired upload.
	UploadByToken(ctx context.Context, tokenHash []byte) (*Upload, error)
	// ClaimUpload makes writer the one writer of the unexpired upload id
	// for lease, unless another writer's claim still holds (false).
	ClaimUpload(ctx context.Context, id int64, writer string, lease time.Duration) (bool, error)
	// ExtendUpload renews writer's claim for lease and keeps the upload
	// for keep from now; false if writer no longer holds the claim.
	ExtendUpload(ctx context.Context, id int64, writer string, lease, keep time.Duration) (bool, error)
	// ReleaseUpload ends writer's claim and keeps the upload for keep from
	// now.
	ReleaseUpload(ctx context.Context, id int64, writer string, keep time.Duration) error
	DeleteUpload(ctx context.Context, id int64) error
	// TakeExpiredUploads deletes up to limit expired uploads that no
	// writer claims, and returns them.
	TakeExpiredUploads(ctx context.Context, limit int) ([]Upload, error)
}
