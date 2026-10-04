package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// migrateAccount binds verified ownership without changing the account or its data.
func migrateAccount(ctx context.Context, kv jetstream.KeyValue, name, expectedAccount, uid string) error {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsFunc(name, unicode.IsSpace) || !nkeys.IsValidPublicAccountKey(expectedAccount) || uid == "" || strings.TrimSpace(uid) != uid {
		return fmt.Errorf("invalid migration: expected namespace/serviceaccount, account public key, and verified UID")
	}
	e, err := kv.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("read mapping: %w", err)
	}
	if string(e.Value()) != expectedAccount {
		var record accountRecord
		if json.Unmarshal(e.Value(), &record) == nil && record.Account == expectedAccount && record.UID == uid {
			return nil
		}
		return fmt.Errorf("mapping differs from verified legacy account or is bound to another UID")
	}
	data, err := json.Marshal(accountRecord{Account: expectedAccount, UID: uid})
	if err != nil {
		return err
	}
	if _, err = kv.Update(ctx, name, data, e.Revision()); err != nil {
		return fmt.Errorf("mapping update: %w", err)
	}
	return nil
}
