package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// Resumable uploads speak tus 1.0.0 (https://tus.io/protocols/resumable-upload)
// with its creation, termination and expiration extensions:
//
//	POST /dir/          starts an upload of Upload-Length bytes, named by
//	                    Upload-Metadata; Location says where the data goes
//	HEAD /.uploads/ID   says how much arrived (Upload-Offset)
//	PATCH /.uploads/ID  adds data at Upload-Offset
//	DELETE /.uploads/ID cancels the upload
//
// What arrives is kept even when a request is cut off, in a hidden temp
// file next to the file it becomes, so finishing is a rename. Uploads
// expire upload.resume_window after data last arrived.
const (
	uploadsPrefix = "/.uploads/"
	tusVersion    = "1.0.0"
	tusExtensions = "creation,termination,expiration"
	partialSuffix = ".upload"
)

// One request at a time writes an upload. Its claim lasts claimLease and
// is renewed every claimRenew while data arrives.
var (
	claimLease = time.Minute
	claimRenew = 15 * time.Second
)

// validPartial reports whether name is the temp file of a resumable upload.
func validPartial(name string) bool {
	return strings.HasPrefix(name, tempPrefix) && strings.HasSuffix(name, partialSuffix) &&
		len(name) <= 64 && !strings.ContainsAny(name, `/\`)
}

// tusRequest checks the protocol version of a tus request and marks the
// answer as one.
func tusRequest(c fiber.Ctx) error {
	c.Set("Tus-Resumable", tusVersion)
	if c.Get("Tus-Resumable") != tusVersion {
		c.Set("Tus-Version", tusVersion)
		c.Set("Tus-Extension", tusExtensions)
		return fiber.ErrPreconditionFailed
	}
	return nil
}

// tusMetadata parses Upload-Metadata: comma-separated keys, each with its
// value in base64 after a space, e.g. "filename Zm9vLmlzbw==,replace MQ==".
func tusMetadata(h string) (map[string]string, bool) {
	meta := make(map[string]string)
	if strings.TrimSpace(h) == "" {
		return meta, true
	}
	for pair := range strings.SplitSeq(h, ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(pair), " ")
		v, err := base64.StdEncoding.DecodeString(value)
		if key == "" || err != nil {
			return nil, false
		}
		meta[key] = string(v)
	}
	return meta, true
}

func setExpires(c fiber.Ctx, up *auth.Upload) {
	c.Set("Upload-Expires", up.ExpiresAt.UTC().Format(http.TimeFormat))
}

// createUpload starts a resumable upload into the folder at dirPath (tus
// creation). Upload-Length gives the file's size; Upload-Metadata its name
// as filename and, with replace set to 1, that it may replace a file of
// that name. Everything is checked as for other uploads, so a doomed
// upload is refused before its data is sent. Through the upload link sh,
// it has the link's rights, and a taken name gets a number instead.
func (s *Server) createUpload(c fiber.Ctx, dirPath string, sh *auth.Share) error {
	if err := tusRequest(c); err != nil {
		return err
	}
	length, err := strconv.ParseInt(c.Get("Upload-Length"), 10, 64)
	if err != nil || length < 0 {
		return explain(fiber.ErrBadRequest, "Upload-Length must give the size of the file.")
	}
	if n := c.Request().Header.ContentLength(); n > 0 || n == -1 {
		return explain(fiber.ErrBadRequest, "Send the data in PATCH requests to the upload.")
	}
	meta, ok := tusMetadata(c.Get("Upload-Metadata"))
	name := meta["filename"]
	if !ok || !validName(name) {
		return explain(fiber.ErrBadRequest, badName)
	}
	replace := meta["replace"] == "1" && sh == nil
	if limit := int64(s.cfg.Upload.MaxSize); limit > 0 && length > limit {
		return fiber.ErrRequestEntityTooLarge
	}
	allow, deny := s.visitorRules(c), func() error { return s.deny(c) }
	if sh != nil {
		allow, deny = s.linkUploadRules(sh), linkClosed
	}
	urlPath := path.Join(dirPath, name)
	if create, mayReplace, err := uploadRightsOf(allow, urlPath); err != nil {
		return err
	} else if !create && !mayReplace {
		return deny()
	}
	dir, realDir, err := s.uploadDir(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	create, mayReplace, err := uploadRightsAtOf(allow, urlPath, path.Join(realDir, name))
	if err != nil {
		return err
	} else if !create && !mayReplace {
		return deny()
	}
	rights := uploadRights{create: create, replace: mayReplace, rename: sh != nil}
	if !rights.rename {
		if s.locked(rootName(dirPath), name) {
			return fiber.ErrConflict
		}
		if _, err := checkTarget(dir, name, replace, rights); errors.Is(err, errExists) {
			return fiber.ErrConflict
		} else if err != nil {
			return err
		}
	}

	up := &auth.Upload{Dir: dirPath, Name: name, Length: length, Replace: replace, Temp: tempPrefix + rand.Text() + partialSuffix}
	if u := userOf(c); u != nil {
		up.UserID = u.ID
	}
	if sh != nil {
		// Each file sent counts as a use of the link.
		if err := s.spendLink(c, sh); err != nil {
			return err
		}
		up.ShareID = sh.ID
	}
	f, err := dir.OpenFile(up.Temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return s.uploadError(nil, err)
	}
	_ = f.Close()
	ctx, cancel := dbContext(c)
	defer cancel()
	token, err := s.auth.CreateUpload(ctx, up, s.cfg.Upload.ResumeWindow)
	if err != nil {
		_ = dir.Remove(up.Temp)
		return err
	}
	s.log.Info("upload started", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", urlPath),
		zap.Int64("length", length), zap.Int64("upload", up.ID))
	c.Location(uploadsPrefix + token)
	setExpires(c, up)
	if length == 0 {
		// Nothing will follow: the file is complete already.
		if err := s.completeUpload(c, dir, up, rights); err != nil {
			return err
		}
	}
	return c.SendStatus(fiber.StatusCreated)
}

// upload finds the upload of a request to /.uploads/TOKEN: one the visitor
// started, signed in as now or anonymously. Others look missing.
func (s *Server) upload(c fiber.Ctx) (*auth.Upload, error) {
	if err := tusRequest(c); err != nil {
		return nil, err
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	up, err := s.auth.UploadByToken(ctx, strings.TrimPrefix(c.Path(), uploadsPrefix))
	switch {
	case errors.Is(err, auth.ErrNotFound):
		return nil, fiber.ErrNotFound
	case err != nil:
		return nil, err
	}
	var uid int64
	if u := userOf(c); u != nil {
		uid = u.ID
	}
	if up.UserID != uid {
		return nil, fiber.ErrNotFound
	}
	return up, nil
}

// headUpload says how much of an upload arrived (tus HEAD).
func (s *Server) headUpload(c fiber.Ctx) error {
	up, err := s.upload(c)
	if err != nil {
		return err
	}
	info, err := s.root.Stat(rootName(path.Join(up.Dir, up.Temp)))
	if err != nil {
		// Gone with its folder, or removed: the upload cannot go on.
		s.dropUpload(up)
		return fiber.ErrNotFound
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Upload-Offset", strconv.FormatInt(info.Size(), 10))
	c.Set("Upload-Length", strconv.FormatInt(up.Length, 10))
	setExpires(c, up)
	c.Status(fiber.StatusOK)
	return nil
}

// patchUpload adds data to an upload at Upload-Offset, which has to be
// where what arrived so far ends (tus PATCH). Data that arrives is kept
// even if the request is cut off, so the upload can go on from there.
// Once all of it is there, the file is stored under its name.
func (s *Server) patchUpload(c fiber.Ctx) error {
	up, err := s.upload(c)
	if err != nil {
		return err
	}
	if mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); mediaType != "application/offset+octet-stream" {
		return fiber.ErrUnsupportedMediaType
	}
	offset, err := strconv.ParseInt(c.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		return explain(fiber.ErrBadRequest, "Upload-Offset must say where the data goes.")
	}
	n := int64(c.Request().Header.ContentLength())
	if n < 0 {
		return fiber.ErrLengthRequired
	}
	if offset+n > up.Length {
		return fiber.ErrRequestEntityTooLarge
	}
	urlPath := path.Join(up.Dir, up.Name)
	allow, err := s.uploadAllow(c, up)
	if err != nil {
		return err
	}
	if create, replace, err := uploadRightsOf(allow, urlPath); err != nil {
		return err
	} else if !create && !replace {
		if up.ShareID != 0 {
			return linkClosed()
		}
		return s.deny(c)
	}

	writer := rand.Text()
	ctx, cancel := dbContext(c)
	claimed, err := s.auth.ClaimUpload(ctx, up.ID, writer, claimLease)
	cancel()
	if err != nil {
		return err
	}
	if !claimed {
		// An earlier request still writes it, such as one whose client
		// went away: it times out soon.
		c.Set(fiber.HeaderRetryAfter, "5")
		return fiber.ErrLocked
	}
	// Once the upload is stored or dropped, there is nothing to release.
	defer s.releaseUpload(up, writer)

	dir, realDir, err := s.uploadDir(up.Dir)
	if errors.Is(err, fiber.ErrNotFound) {
		s.dropUpload(up)
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.OpenFile(up.Temp, os.O_WRONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		s.dropUpload(up)
		return fiber.ErrNotFound
	}
	if err != nil {
		return err
	}
	if info, err := f.Stat(); err != nil || info.Size() != offset {
		_ = f.Close()
		if err != nil {
			return err
		}
		c.Set("Upload-Offset", strconv.FormatInt(info.Size(), 10))
		return explain(fiber.ErrConflict, "Upload-Offset is not where the data received so far ends.")
	}
	body := s.requestBody(c)
	stop := s.keepClaim(up, writer, body)
	var written int64
	if _, err = f.Seek(offset, io.SeekStart); err == nil {
		written, err = io.Copy(f, body)
	}
	stop()
	// What arrived stays, also when the request was cut off.
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return s.uploadError(body, err)
	}
	s.finishBody(c, body)
	offset += written
	c.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	setExpires(c, up)
	if offset < up.Length {
		return c.SendStatus(fiber.StatusNoContent)
	}

	create, replace, err := uploadRightsAtOf(allow, urlPath, path.Join(realDir, up.Name))
	if err != nil {
		return err
	}
	if err := s.completeUpload(c, dir, up, uploadRights{create: create, replace: replace, rename: up.ShareID != 0}); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// uploadAllow returns the rules an unfinished upload is written with: the
// visitor's, or those of the upload link it came through, while that works.
func (s *Server) uploadAllow(c fiber.Ctx, up *auth.Upload) (allowFunc, error) {
	if up.ShareID == 0 {
		return s.visitorRules(c), nil
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	sh, err := s.auth.ShareByID(ctx, up.ShareID)
	if errors.Is(err, auth.ErrNotFound) {
		s.dropUpload(up)
		return nil, explain(fiber.ErrNotFound, deadLink)
	}
	if err != nil {
		return nil, err
	}
	return s.linkUploadRules(sh), nil
}

// linkClosed refuses an upload through a link whose creator may no longer
// add files where it leads.
func linkClosed() error {
	return explain(fiber.ErrForbidden, "This link no longer lets anyone send files.")
}

// completeUpload stores a complete upload under its name, as receive does
// for other uploads, and forgets it. If the name is busy, the upload waits
// for the next try (423), as it does after other failures that may pass,
// such as a full disk. If it may not be stored at all, it is dropped.
func (s *Server) completeUpload(c fiber.Ctx, dir *os.Root, up *auth.Upload, rights uploadRights) error {
	release, err := s.acquireLock(dir, up.Name, tempPrefix+rand.Text()+tempSuffix)
	if errors.Is(err, fiber.ErrConflict) {
		c.Set(fiber.HeaderRetryAfter, "5")
		return fiber.ErrLocked
	}
	if err != nil {
		return err
	}
	defer release()
	name, created := up.Name, true
	switch {
	case rights.rename && !rights.create:
		err = fiber.ErrForbidden
	case rights.rename:
		name, err = s.placeFree(dir, up.Temp, up.Name)
	default:
		created, err = checkTarget(dir, up.Name, up.Replace, rights)
		if err == nil {
			err = place(dir, up.Temp, up.Name, up.Replace, rights)
		}
	}
	if errors.Is(err, errExists) {
		err = fiber.ErrConflict
	}
	if errors.Is(err, fs.ErrNotExist) {
		// The folder was deleted meanwhile.
		err = fiber.ErrNotFound
	}
	var fe *fiber.Error
	if err != nil && !errors.As(err, &fe) {
		// Such as a full disk: the upload stays, to try again.
		return s.uploadError(nil, err)
	}
	if err != nil {
		s.dropUpload(up)
		return err
	}
	// Linking leaves the temp file behind.
	_ = dir.Remove(up.Temp)
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := s.auth.DeleteUpload(ctx, up.ID); err != nil {
		s.log.Warn("forget upload", zap.Int64("upload", up.ID), zap.Error(err))
	}
	s.logUpload(c, path.Join(up.Dir, name), up.Length, created)
	return nil
}

// deleteUpload cancels an upload and removes what arrived (tus
// termination).
func (s *Server) deleteUpload(c fiber.Ctx) error {
	up, err := s.upload(c)
	if err != nil {
		return err
	}
	ctx, cancel := dbContext(c)
	claimed, err := s.auth.ClaimUpload(ctx, up.ID, rand.Text(), claimLease)
	cancel()
	if err != nil {
		return err
	}
	if !claimed {
		c.Set(fiber.HeaderRetryAfter, "5")
		return fiber.ErrLocked
	}
	s.dropUpload(up)
	s.log.Info("upload cancelled", zap.String("ip", c.IP()), zap.String("user", visitor(c)),
		zap.String("path", path.Join(up.Dir, up.Name)), zap.Int64("upload", up.ID))
	return c.SendStatus(fiber.StatusNoContent)
}

// keepClaim renews writer's claim on up while body is read, and stops the
// body if the claim is lost: another request may write then.
func (s *Server) keepClaim(up *auth.Upload, writer string, body *requestBody) (stop func()) {
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(claimRenew)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
				ok, err := s.auth.ExtendUpload(ctx, up.ID, writer, claimLease, s.cfg.Upload.ResumeWindow)
				cancel()
				if !ok || err != nil {
					s.log.Warn("upload claim lost", zap.Int64("upload", up.ID), zap.Error(err))
					body.abort()
					return
				}
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func (s *Server) releaseUpload(up *auth.Upload, writer string) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := s.auth.ReleaseUpload(ctx, up.ID, writer, s.cfg.Upload.ResumeWindow); err != nil {
		s.log.Warn("release upload", zap.Int64("upload", up.ID), zap.Error(err))
	}
}

// dropUpload forgets an upload and removes what arrived.
func (s *Server) dropUpload(up *auth.Upload) {
	s.removePartial(up)
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := s.auth.DeleteUpload(ctx, up.ID); err != nil {
		s.log.Warn("forget upload", zap.Int64("upload", up.ID), zap.Error(err))
	}
}

// removePartial removes what arrived for an upload, if its folder is still
// there; otherwise removeLeftovers finds it once it is old.
func (s *Server) removePartial(up *auth.Upload) {
	if validPartial(up.Temp) {
		_ = s.root.Remove(rootName(path.Join(up.Dir, up.Temp)))
	}
}

// purgeUploads removes expired uploads with what they received, every
// purgeEvery until ctx ends.
func (s *Server) purgeUploads(ctx context.Context) {
	const batch = 100
	for {
		for {
			ups, err := s.auth.TakeExpiredUploads(ctx, batch)
			if err != nil {
				if ctx.Err() == nil {
					s.log.Warn("purge uploads", zap.Error(err))
				}
				break
			}
			for i := range ups {
				s.removePartial(&ups[i])
			}
			if len(ups) > 0 {
				s.log.Info("removed expired uploads", zap.Int("uploads", len(ups)))
			}
			if len(ups) < batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(purgeEvery):
		}
	}
}

var purgeEvery = time.Hour
