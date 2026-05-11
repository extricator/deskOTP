// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package vault

import (
	"encoding/json"

	"deskotp/internal/entries"
	"deskotp/internal/totp"
)

// vaultPayload is the plaintext structure encrypted inside AES-256-GCM.
// Old vaults encrypted a bare []totp.Entry JSON array; new vaults use this struct.
// Backward compatibility: decryptPayload detects old format by checking if
// the first byte is '[' (array) vs '{' (object).
// Groups used to be []string; unmarshalGroups handles both formats transparently.
type vaultPayload struct {
	Entries []totp.Entry        `json:"entries"`
	Groups  []entries.GroupInfo `json:"groups"`
}

// marshalPayload serializes entries and groups into the JSON plaintext
// that will be encrypted. Both Encrypt and EncryptWithKey use this.
func marshalPayload(ents []totp.Entry, groups []entries.GroupInfo) ([]byte, error) {
	if groups == nil {
		groups = []entries.GroupInfo{}
	}
	return json.Marshal(vaultPayload{Entries: ents, Groups: groups})
}
