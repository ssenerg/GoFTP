package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"goftp/internal/auth"
)

func TestUploads(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		up := &auth.Upload{UserID: 7, Dir: "/d", Name: "a.bin", Length: 10, Replace: true, Temp: ".goftp-A.upload"}
		token, err := svc.CreateUpload(ctx, up, time.Hour)
		if err != nil || up.ID == 0 || up.CreatedAt.IsZero() || time.Until(up.ExpiresAt) < 59*time.Minute || !auth.ValidToken(token) {
			t.Fatalf("CreateUpload: %+v %v", up, err)
		}
		got, err := svc.UploadByToken(ctx, token)
		if err != nil || got.ID != up.ID || got.UserID != 7 || got.Dir != "/d" || got.Name != "a.bin" || got.Length != 10 || !got.Replace || got.Temp != ".goftp-A.upload" {
			t.Fatalf("UploadByToken: %+v %v", got, err)
		}
		for _, bad := range []string{"", "x", token[:42], token + "x"} {
			if _, err := svc.UploadByToken(ctx, bad); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("UploadByToken(%q): %v", bad, err)
			}
		}
		if !got.Mtime.IsZero() {
			t.Errorf("a time without one: %v", got.Mtime)
		}
		// The modification time the file gets.
		timed := &auth.Upload{UserID: 7, Dir: "/d", Name: "b.bin", Length: 1, Temp: ".goftp-B.upload", Mtime: time.Unix(1700000000, 0)}
		timedToken, err := svc.CreateUpload(ctx, timed, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := svc.UploadByToken(ctx, timedToken); err != nil || !got.Mtime.Equal(time.Unix(1700000000, 0)) {
			t.Errorf("with a time: %+v %v", got, err)
		}

		// One writer at a time; a claim that ran out can be taken over.
		claim := func(writer string, lease time.Duration) bool {
			t.Helper()
			ok, err := svc.ClaimUpload(ctx, up.ID, writer, lease)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		extend := func(writer string, lease, keep time.Duration) bool {
			t.Helper()
			ok, err := svc.ExtendUpload(ctx, up.ID, writer, lease, keep)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !claim("w1", time.Minute) || claim("w2", time.Minute) {
			t.Fatal("two writers")
		}
		if extend("w2", time.Minute, time.Hour) || !extend("w1", time.Minute, 2*time.Hour) {
			t.Error("only the writer extends its claim")
		}
		if got, _ := svc.UploadByToken(ctx, token); time.Until(got.ExpiresAt) < 119*time.Minute {
			t.Errorf("not kept longer: %v", got.ExpiresAt)
		}
		if err := svc.ReleaseUpload(ctx, up.ID, "w2", time.Hour); err != nil || claim("w2", time.Minute) {
			t.Error("another writer released the claim")
		}
		if err := svc.ReleaseUpload(ctx, up.ID, "w1", time.Hour); err != nil || !claim("w2", -time.Second) {
			t.Error("a released claim cannot be taken")
		}
		if !claim("w3", time.Minute) {
			t.Error("a claim that ran out cannot be taken over")
		}
		if err := svc.ReleaseUpload(ctx, up.ID, "w3", time.Hour); err != nil {
			t.Fatal(err)
		}

		// Expired uploads are gone, and taken for removal once no writer
		// works on them.
		old := &auth.Upload{Dir: "/d", Name: "b.bin", Length: 1, Temp: ".goftp-B.upload"}
		oldToken, err := svc.CreateUpload(ctx, old, -time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UploadByToken(ctx, oldToken); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("expired upload: %v", err)
		}
		if ok, _ := svc.ClaimUpload(ctx, old.ID, "w", time.Minute); ok {
			t.Error("claimed an expired upload")
		}
		busy := &auth.Upload{Dir: "/d", Name: "c.bin", Length: 1, Temp: ".goftp-C.upload"}
		if _, err := svc.CreateUpload(ctx, busy, time.Hour); err != nil {
			t.Fatal(err)
		}
		if ok, _ := svc.ClaimUpload(ctx, busy.ID, "w", time.Hour); !ok {
			t.Fatal("claim")
		}
		if ok, _ := svc.ExtendUpload(ctx, busy.ID, "w", time.Hour, -time.Second); !ok {
			t.Fatal("extend")
		}
		taken, err := svc.TakeExpiredUploads(ctx, 10)
		if err != nil || len(taken) != 1 || taken[0].ID != old.ID || taken[0].Temp != ".goftp-B.upload" {
			t.Errorf("TakeExpiredUploads: %+v %v", taken, err)
		}
		if ok, _ := svc.ExtendUpload(ctx, busy.ID, "w", -time.Second, -time.Second); !ok {
			t.Fatal("extend")
		}
		if taken, _ := svc.TakeExpiredUploads(ctx, 10); len(taken) != 1 || taken[0].ID != busy.ID {
			t.Errorf("an expired upload whose writer stopped was not taken: %+v", taken)
		}
		if taken, _ := svc.TakeExpiredUploads(ctx, 10); len(taken) != 0 {
			t.Errorf("taken twice: %+v", taken)
		}

		if err := svc.DeleteUpload(ctx, up.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UploadByToken(ctx, token); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("deleted upload: %v", err)
		}
	})
}
