package entity

import "github.com/tacenva/tacpass-core/util/keyring"

type SyncMode string

const (
	SyncModeManual SyncMode = "manual"
	SyncModeAuto   SyncMode = "auto"
)

type SourceOfTruth struct {
	ID             string          `json:"id"`
	Hostname       string          `json:"hostname"`
	Address        string          `json:"address"`
	AuthToken      string          `json:"auth_token"`
	HashSync       string          `json:"hash_sync"`
	SyncMode       SyncMode        `json:"sync_mode"`
	KeyPair        keyring.KeyPair `json:"key_pair"`
	TLSFingerprint string          `json:"tls_fingerprint"`
}
