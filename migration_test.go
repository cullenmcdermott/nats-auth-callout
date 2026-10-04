package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestMigrateAccount(t *testing.T) {
	m := keys("test-migration-master-secret-32-bytes")
	admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: adminClient})
	url, stop := boot(t, t.TempDir(), m, fakeKube(t), admin)
	defer stop()
	nc, err := connect(url, "migration-test", pub(operatorSecret.auth()), m.authSigner(), m.user("callout"))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	kv, err := js.KeyValue(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := nkeys.CreateAccount()
	account := pub(key)
	other, _ := nkeys.CreateAccount()
	another := pub(other)
	for name, c := range map[string]struct {
		row                    []byte
		mapping, expected, uid string
	}{
		"wrong key":           {[]byte(account), "test/worker", another, "owner"},
		"missing uid":         {[]byte(account), "test/worker", account, ""},
		"padded uid":          {[]byte(account), "test/worker", account, " owner "},
		"malformed name":      {[]byte(account), "test/worker/extra", account, "owner"},
		"empty namespace":     {[]byte(account), "/worker", account, "owner"},
		"invalid key":         {[]byte(account), "test/worker", "bad-key", "owner"},
		"malformed value":     {[]byte("not-an-account"), "test/worker", account, "owner"},
		"other UID":           {[]byte(`{"account":"` + account + `","uid":"other"}`), "test/worker", account, "owner"},
		"other bound account": {[]byte(`{"account":"` + another + `","uid":"owner"}`), "test/worker", account, "owner"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := kv.Put(ctx, "test/worker", c.row); err != nil {
				t.Fatal(err)
			}
			before, err := kv.Get(ctx, "test/worker")
			if err != nil {
				t.Fatal(err)
			}
			if err := migrateAccount(ctx, kv, c.mapping, c.expected, c.uid); err == nil {
				t.Fatal("unsafe migration accepted")
			}
			after, err := kv.Get(ctx, "test/worker")
			if err != nil {
				t.Fatal(err)
			}
			if after.Revision() != before.Revision() || string(after.Value()) != string(before.Value()) {
				t.Fatal("denial modified existing mapping")
			}
		})
	}
	t.Run("missing row", func(t *testing.T) {
		if err := migrateAccount(ctx, kv, "absent/worker", account, "owner"); err == nil {
			t.Fatal("missing row accepted")
		}
		if _, err := kv.Get(ctx, "absent/worker"); err == nil {
			t.Fatal("missing row created")
		}
	})
	t.Run("preserve account and idempotent", func(t *testing.T) {
		if _, err := kv.Put(ctx, "test/worker", []byte(account)); err != nil {
			t.Fatal(err)
		}
		if err := migrateAccount(ctx, kv, "test/worker", account, "owner"); err != nil {
			t.Fatal(err)
		}
		before, err := kv.Get(ctx, "test/worker")
		if err != nil {
			t.Fatal(err)
		}
		var record accountRecord
		if err := json.Unmarshal(before.Value(), &record); err != nil {
			t.Fatal(err)
		}
		if record.Account != account || record.UID != "owner" {
			t.Fatalf("wrong record: %+v", record)
		}
		if err := migrateAccount(ctx, kv, "test/worker", account, "owner"); err != nil {
			t.Fatal(err)
		}
		after, err := kv.Get(ctx, "test/worker")
		if err != nil {
			t.Fatal(err)
		}
		if after.Revision() != before.Revision() {
			t.Fatal("idempotent migration rewrote record")
		}
		if err := migrateAccount(ctx, kv, "test/worker", account, "replacement"); err == nil {
			t.Fatal("rebound migrated account")
		}
		after, err = kv.Get(ctx, "test/worker")
		if err != nil {
			t.Fatal(err)
		}
		if after.Revision() != before.Revision() {
			t.Fatal("replacement UID modified record")
		}
	})
}
