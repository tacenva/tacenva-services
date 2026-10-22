package entity

import (
	coreEntity "github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type SyncMode string

const (
	SyncModeManual SyncMode = "manual"
	SyncModeAuto   SyncMode = "auto"
)

type SourceOfTruth struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Address  string   `json:"address"`
	SyncMode SyncMode `json:"sync_mode"`

	AuthToken  string                `json:"auth_token"`
	UserStatus coreEntity.UserStatus `json:"user_status"`
	KeyPair    keyring.KeyPair       `json:"key_pair"`
	GroupID    string                `json:"group_id"`

	TLSFingerprint string `json:"tls_fingerprint"`
}
