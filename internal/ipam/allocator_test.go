package ipam

import (
	"testing"
)

func TestAllocator_FirstAllocationStartsAtDotTwo(t *testing.T) {
	a, err := New(map[string]string{
		"admins": "10.100.10.0/24",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ip, err := a.Allocate("admins", map[string]struct{}{})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if ip != "10.100.10.2" {
		t.Errorf("first allocation = %q, want 10.100.10.2 (skipping .0 network and .1 gateway)", ip)
	}
}

func TestAllocator_SkipsUsed(t *testing.T) {
	a, err := New(map[string]string{"admins": "10.100.10.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]struct{}{
		"10.100.10.2": {},
		"10.100.10.3": {},
	}
	got, err := a.Allocate("admins", used)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.100.10.4" {
		t.Errorf("got %q, want 10.100.10.4", got)
	}
}

func TestAllocator_Exhaustion(t *testing.T) {
	a, err := New(map[string]string{"tiny": "10.0.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]struct{}{
		"10.0.0.2": {},
	}
	_, err = a.Allocate("tiny", used)
	if err == nil {
		t.Fatal("expected exhaustion error, got nil")
	}
}

func TestAllocator_UnknownGroup(t *testing.T) {
	a, _ := New(map[string]string{"admins": "10.100.10.0/24"})
	if _, err := a.Allocate("ghost", nil); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestAllocator_BadCIDR(t *testing.T) {
	if _, err := New(map[string]string{"admins": "not-a-cidr"}); err == nil {
		t.Fatal("expected error for bad cidr")
	}
}

func TestGroupForUserGroups_PrefersUserGroup(t *testing.T) {
	a, _ := New(map[string]string{
		"admins": "10.100.10.0/24",
		"guests": "10.100.30.0/24",
	})
	got := a.GroupForUserGroups([]string{"unknown", "admins"}, "guests")
	if got != "admins" {
		t.Errorf("got %q, want admins", got)
	}
}

func TestGroupForUserGroups_FallsBackToDefault(t *testing.T) {
	a, _ := New(map[string]string{
		"admins": "10.100.10.0/24",
		"guests": "10.100.30.0/24",
	})
	got := a.GroupForUserGroups([]string{"unrelated"}, "guests")
	if got != "guests" {
		t.Errorf("got %q, want guests fallback", got)
	}
}

func TestGroupForUserGroups_NoMatchNoDefault(t *testing.T) {
	a, _ := New(map[string]string{
		"admins": "10.100.10.0/24",
	})
	got := a.GroupForUserGroups([]string{"nope"}, "")
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestGroupForUserGroups_BogusDefaultIsIgnored(t *testing.T) {
	a, _ := New(map[string]string{
		"admins": "10.100.10.0/24",
	})
	got := a.GroupForUserGroups([]string{"nope"}, "ghost")
	if got != "" {
		t.Errorf("got %q, want empty (bogus default)", got)
	}
}
