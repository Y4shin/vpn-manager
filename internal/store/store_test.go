package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestUpsertUser_InsertAndUpdate(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()

	u, err := st.UpsertUser(ctx, "sub-1", "a@example.com", []string{"admins"})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if u.ID == 0 {
		t.Errorf("ID should be set")
	}
	if u.Email != "a@example.com" {
		t.Errorf("email: %q", u.Email)
	}
	if len(u.Groups) != 1 || u.Groups[0] != "admins" {
		t.Errorf("groups: %v", u.Groups)
	}

	u2, err := st.UpsertUser(ctx, "sub-1", "a-new@example.com", []string{"guests"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u2.ID != u.ID {
		t.Errorf("upsert should keep the same id: %d -> %d", u.ID, u2.ID)
	}
	if u2.Email != "a-new@example.com" {
		t.Errorf("update email: %q", u2.Email)
	}
	if u2.Groups[0] != "guests" {
		t.Errorf("update groups: %v", u2.Groups)
	}
}

func TestDeviceLifecycle(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	user, err := st.UpsertUser(ctx, "sub-x", "x@example.com", []string{"admins"})
	if err != nil {
		t.Fatal(err)
	}

	id, err := st.CreateDevice(ctx, &Device{
		UserID: user.ID, Name: "laptop",
		PublicKey: "PUB1=", IP: "10.100.10.2", GroupAtCreation: "admins",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	devs, err := st.ListDevicesByUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].ID != id || devs[0].IP != "10.100.10.2" {
		t.Errorf("list: %+v", devs)
	}

	used, err := st.UsedIPs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := used["10.100.10.2"]; !ok {
		t.Errorf("expected 10.100.10.2 in used set: %v", used)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := st.UpdateHandshake(ctx, "PUB1=", now); err != nil {
		t.Fatalf("update handshake: %v", err)
	}
	devs, _ = st.ListDevicesByUser(ctx, user.ID)
	if devs[0].LastHandshakeAt == nil || !devs[0].LastHandshakeAt.Equal(now) {
		t.Errorf("last handshake: %v, want %v", devs[0].LastHandshakeAt, now)
	}

	if err := st.DeleteDevice(ctx, user.ID, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	devs, _ = st.ListDevicesByUser(ctx, user.ID)
	if len(devs) != 0 {
		t.Errorf("after delete, expected 0 devices, got %d", len(devs))
	}
}

func TestDeleteDevice_RejectsOtherUsers(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	alice, _ := st.UpsertUser(ctx, "alice", "a@x", []string{"admins"})
	bob, _ := st.UpsertUser(ctx, "bob", "b@x", []string{"admins"})

	id, err := st.CreateDevice(ctx, &Device{
		UserID: alice.ID, Name: "a-laptop",
		PublicKey: "AK=", IP: "10.100.10.2", GroupAtCreation: "admins",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteDevice(ctx, bob.ID, id); err == nil {
		t.Fatal("expected error: bob should not be able to delete alice's device")
	}

	devs, _ := st.ListDevicesByUser(ctx, alice.ID)
	if len(devs) != 1 {
		t.Errorf("alice's device should still exist; got %d", len(devs))
	}
}

func TestUniqueConstraints(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	u, _ := st.UpsertUser(ctx, "u", "u@x", nil)
	if _, err := st.CreateDevice(ctx, &Device{UserID: u.ID, Name: "a", PublicKey: "K=", IP: "10.0.0.2", GroupAtCreation: "g"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateDevice(ctx, &Device{UserID: u.ID, Name: "b", PublicKey: "K=", IP: "10.0.0.3", GroupAtCreation: "g"}); err == nil {
		t.Error("expected unique-pubkey violation")
	}
	if _, err := st.CreateDevice(ctx, &Device{UserID: u.ID, Name: "c", PublicKey: "K2=", IP: "10.0.0.2", GroupAtCreation: "g"}); err == nil {
		t.Error("expected unique-ip violation")
	}
}
