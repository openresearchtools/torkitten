package state

import (
	"os"
	"path/filepath"
	"testing"

	"torkitten/internal/model"
)

const testServiceID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

func TestStoreRoundTripIsSortedAndPrivate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "state.json")
	store := NewStore(path)
	want := model.NewState(testServiceID)
	want.Mappings = []model.Mapping{
		{Prefix: "wiki", Port: 8888, Scheme: model.SchemeHTTP, Enable: true},
		{Prefix: "api", Port: 7777, Scheme: model.SchemeHTTP, Enable: true},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("state permissions = %o, want 600", permissions)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Mappings) != 2 || got.Mappings[0].Prefix != "api" || got.Mappings[1].Prefix != "wiki" {
		t.Fatalf("stored mappings are not sorted: %#v", got.Mappings)
	}
}

func TestStoreRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	content := []byte(`{"version":1,"service_id":"` + testServiceID + `","mappings":[],"surprise":true}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}
