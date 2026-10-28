package entity

import (
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/util/keyring"
)

type SyncMode string

const (
	SyncModeManual SyncMode = "manual"
	SyncModeAuto   SyncMode = "auto"
)

type SourceOfTruth struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	Address  string    `json:"address"`
	SyncMode *SyncMode `json:"sync_mode,omitempty"`

	Auth        *Auth        `json:"auth,omitempty"`
	AccessGroup *AccessGroup `json:"access_group,omitempty"`

	TLSFingerprint string `json:"tls_fingerprint"`
}

type AccessGroup struct {
	ID      string          `json:"id"`
	KeyPair keyring.KeyPair `json:"key_pair"`
}

type Auth struct {
	Token               string                    `json:"token"`
	Status              tacenvaentity.UserStatus  `json:"status"`
	Level               tacenvaentity.AccessLevel `json:"level"`
	KeyPairOfAccessUnit keyring.KeyPair           `json:"key_pair"`
}
