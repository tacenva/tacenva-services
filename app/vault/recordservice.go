package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/config"
	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/contract"
	coreEntity "github.com/tacenva/tacpass-core/entity"
)

func (s *Service) AppendRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	if vault == nil {
		return nil, errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, errors.New(
			"vault id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	encrypted, err := s.vaultrecordService.Local.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	var (
		syncChangeID string
		recordID     string
	)

	if !s.context.IsRemote {
		err = s.vaultrecordService.Local.CreateOnSot(
			s.context.AuthorizedUser,
			&recordID,
			[]byte(encrypted),
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return nil, err
		}
	} else {
		err = s.vaultrecordService.Local.CreateOnReplica(
			&recordID,
			[]byte(encrypted),
			&syncChangeID,
		)
		if err != nil {
			return nil, err
		}
	}

	record.ID = recordID

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vault)
		if err != nil {
			return nil, err
		}
	}
	return record, nil
}

func (s *Service) UpdateRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	if vault == nil {
		return nil, errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, errors.New(
			"vault id cannot be empty",
		)
	}

	if record.ID == "" {
		return nil, errors.New(
			"record id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	encrypted, err := s.vaultrecordService.Local.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	var syncChangeID string

	if !s.context.IsRemote {
		err = s.vaultrecordService.Local.UpdateOnSot(
			s.context.AuthorizedUser,
			record.ID,
			[]byte(encrypted),
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return nil, err
		}
	} else {
		err = s.vaultrecordService.Local.UpdateOnReplica(
			record.ID,
			[]byte(encrypted),
			&syncChangeID,
		)
		if err != nil {
			return nil, err
		}
	}

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vault)
		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

func (s *Service) DeleteRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
) error {
	if vault == nil {
		return errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return errors.New(
			"vault id cannot be empty",
		)
	}

	if record.ID == "" {
		return errors.New(
			"record id cannot be empty",
		)
	}

	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return errors.New(
			"selected source of truth is nil",
		)
	}

	var syncChangeID string
	if !s.context.IsRemote {
		err := s.vaultrecordService.Local.DeleteOnSot(
			s.context.AuthorizedUser,
			record.ID,
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return err
		}
	} else {
		err := s.vaultrecordService.Local.DeleteOnReplica(
			record.ID,
			&syncChangeID,
		)
		if err != nil {
			return err
		}
	}

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		err := s.SyncRecord(vault)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) SyncRecord(
	vault *coreEntity.Vault,
) error {
	// startedAt := time.Now()

	// log.Printf(
	// 	"[SyncRecord] started: vault_id=%s",
	// 	vault.ID,
	// )

	// log.Printf("[SyncRecord] getting local latest change ID")

	lastChangeID, err := s.vaultrecordService.Local.GetSyncLatestChangeId()
	if err != nil {
		// log.Printf("[SyncRecord] failed to get latest change ID: %v", err)
		return err
	}

	// log.Printf(
	// 	"[SyncRecord] latest change ID: %s",
	// 	lastChangeID,
	// )

	// log.Printf("[SyncRecord] getting local record changes")

	localChanges, err := s.getLocalRecordChanges(lastChangeID)
	if err != nil {
		// log.Printf("[SyncRecord] failed to get local changes: %v", err)
		return err
	}

	// localCount := 0
	// if localChanges != nil {
	// 	localCount = len(localChanges.SyncChanges)
	// }

	// log.Printf(
	// 	"[SyncRecord] local changes fetched: count=%d",
	// 	localCount,
	// )

	// log.Printf("[SyncRecord] getting remote record changes")

	clientChanges, clientChangeTotal, err := s.getClientRecordChanges(
		vault.ID,
		lastChangeID,
	)
	if err != nil {
		// log.Printf("[SyncRecord] failed to get remote changes: %v", err)
		return err
	}

	remoteCount := int64(0)
	if clientChangeTotal != nil {
		remoteCount = clientChangeTotal.Count
	}

	// log.Printf(
	// 	"[SyncRecord] remote changes fetched: count=%d",
	// 	remoteCount,
	// )

	// log.Printf("[SyncRecord] sending changes to server")

	err = s.appDeps.Client.SyncRecords(
		s.context.SelectedSot.Address,
		vault.ID,
		lastChangeID,
		int(remoteCount),
		localChanges,
	)
	if err != nil {
		// log.Printf("[SyncRecord] server sync failed: %v", err)
		return err
	}

	// log.Printf("[SyncRecord] server sync completed")

	// log.Printf("[SyncRecord] applying changes locally")

	if err := s.vaultrecordService.Local.SyncOnReplica(
		clientChanges,
		localChanges,
	); err != nil {
		// log.Printf("[SyncRecord] local sync failed: %v", err)
		return err
	}

	// log.Printf("[SyncRecord] local sync completed")

	// log.Printf("[SyncRecord] updating sync state")

	if err := s.vaultrecordService.Local.SetSyncStateToBeLatest(); err != nil {
		// log.Printf("[SyncRecord] failed to update sync state: %v", err)
		return err
	}

	// log.Printf(
	// 	"[SyncRecord] completed: vault_id=%s, duration=%s",
	// 	vault.ID,
	// 	time.Since(startedAt),
	// )

	return nil
}

func (s *Service) getLocalRecordChanges(
	lastChangeID string,
) (*contract.PendingVaultRecordChange, error) {
	changeCount, err := s.vaultrecordService.Local.GetChangeCount(
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if changeCount == 0 {
		return nil, nil
	}

	return s.vaultrecordService.Local.GetChangesAfter(
		lastChangeID,
		int(changeCount),
	)
}

func (s *Service) getClientRecordChanges(
	vaultID string,
	lastChangeID string,
) (*contract.PendingVaultRecordChange, *contract.PendingTotalChanges, error) {
	changeCount, err := s.appDeps.Client.GetRecordChangesCount(
		s.context.SelectedSot.Address,
		vaultID,
		lastChangeID,
	)
	if err != nil {
		return nil, nil, err
	}

	if changeCount.Count == 0 {
		return nil, changeCount, nil
	}

	pendingChanges, err := s.appDeps.Client.GetRecordChanges(
		s.context.SelectedSot.Address,
		vaultID,
		lastChangeID,
		int(changeCount.Count),
	)
	if err != nil {
		return nil, nil, err
	}

	return pendingChanges, changeCount, nil
}

func (s *Service) SelectVault(
	vault *coreEntity.Vault,
	wrappedVaultKey string,
) error {
	if vault == nil {
		err := errors.New("vault cannot be nil")
		// log.Printf("[SelectVault] validation failed: %v", err)
		return err
	}

	if vault.ID == "" {
		err := errors.New("vault id cannot be empty")
		// log.Printf("[SelectVault] validation failed: %v", err)
		return err
	}

	if s.context == nil {
		err := errors.New("context is nil")
		// log.Printf("[SelectVault] validation failed: %v", err)
		return err
	}

	if s.context.SelectedSot == nil {
		err := errors.New("selected source of truth is nil")
		// log.Printf("[SelectVault] validation failed: %v", err)
		return err
	}

	unwrappedVaultKey, err :=
		s.context.SelectedSot.AccessGroup.KeyPair.Open(wrappedVaultKey)
	if err != nil {
		// log.Printf("[SelectVault] failed to unwrap vault key: %v", err)
		return err
	}

	vaultDir := s.appDeps.Config.Path(
		config.NodeDirName,
		s.context.SelectedSot.ID,
		"vault",
	)

	err = s.vaultrecordService.Local.SetConfig(
		vaultDir,
		s.context.SelectedSot.ID,
		vault.ID,
		string(unwrappedVaultKey),
	)

	if err == nil {
		return nil
	}

	if !errors.Is(err, database.ErrFileNotFound) {
		// log.Printf("[SelectVault] failed to set local vault config: %v", err)
		return err
	}

	if !s.context.IsRemote {
		// log.Printf(
		// 	"[SelectVault] vault file not found and source is local: vault_id=%s",
		// 	vault.ID,
		// )
		return err
	}

	recordsBlob, err := s.appDeps.Client.GetRecordBlob(
		s.context.SelectedSot.Address,
		vault.ID,
	)
	if err != nil {
		// log.Printf("[SelectVault] failed to download record blob: %v", err)
		return err
	}

	if err := s.vaultrecordService.Local.StoreBlob(recordsBlob); err != nil {
		// log.Printf("[SelectVault] failed to store record blob: %v", err)
		return err
	}

	if err := s.vaultrecordService.Local.OpenVaultDbFile(); err != nil {
		// log.Printf("[SelectVault] failed to open vault database file: %v", err)
		return err
	}

	if err := s.vaultrecordService.Local.SetConfig(
		vaultDir,
		s.context.SelectedSot.ID,
		vault.ID,
		string(unwrappedVaultKey),
	); err != nil {
		// log.Printf("[SelectVault] failed to set vault config after download: %v", err)
		return err
	}

	return nil
}

func (s *Service) ListRecord(
	vault *coreEntity.Vault,
) ([]coreEntity.VaultRecord, bool, error) {
	var records []coreEntity.VaultRecord

	withError := func(err error, hasChanges bool) ([]coreEntity.VaultRecord, bool, error) {
		return records, hasChanges, err
	}

	if vault == nil {
		err := errors.New("vault cannot be nil")
		// log.Printf("[ListRecord] validation failed: %v", err)
		return withError(err, false)
	}

	if s.context == nil {
		err := errors.New("context is nil")
		// log.Printf("[ListRecord] validation failed: vault_id=%s, error=%v", vault.ID, err)
		return withError(err, false)
	}

	if s.context.SelectedSot == nil {
		err := errors.New("selected source of truth is nil")
		// log.Printf("[ListRecord] validation failed: vault_id=%s, error=%v", vault.ID, err)
		return withError(err, false)
	}

	// log.Printf("[ListRecord] loading local records: vault_id=%s", vault.ID)

	var err error
	records, err = s.vaultrecordService.Local.List()
	if err != nil {
		// log.Printf("[ListRecord] failed to list local records: vault_id=%s, error=%v", vault.ID, err)
		return withError(err, false)
	}

	if !s.context.IsRemote {
		// log.Printf("[ListRecord] skipping sync: source is local, vault_id=%s", vault.ID)
		return withError(nil, false)
	}

	if !s.appDeps.Client.IsReachable() {
		// log.Printf("[ListRecord] skipping sync: client is unreachable, vault_id=%s", vault.ID)
		return withError(nil, false)
	}

	switch s.context.SelectedSot.SyncMode {
	case operationsEntity.SyncModeAuto:
		// log.Printf("[ListRecord] starting automatic sync: vault_id=%s", vault.ID)

		if err := s.SyncRecord(vault); err != nil {
			// log.Printf("[ListRecord] automatic sync failed: vault_id=%s, error=%v", vault.ID, err)
			return withError(err, true)
		}

		records, err = s.vaultrecordService.Local.List()
		if err != nil {
			// log.Printf("[ListRecord] failed to reload records after sync: vault_id=%s, error=%v", vault.ID, err)
			return withError(err, false)
		}

		// log.Printf("[ListRecord] automatic sync completed: vault_id=%s, records=%d", vault.ID, len(records))
		return withError(nil, false)

	case operationsEntity.SyncModeManual:
		// log.Printf("[ListRecord] checking manual sync changes: vault_id=%s", vault.ID)

		lastChangeID, err := s.vaultrecordService.Local.GetSyncLatestChangeId()
		if err != nil {
			// log.Printf("[ListRecord] failed to get latest sync change ID: vault_id=%s, error=%v", vault.ID, err)
			return withError(err, true)
		}

		totalChanges, err := s.vaultrecordService.Local.GetChangeCount(lastChangeID)
		if err != nil {
			// log.Printf("[ListRecord] failed to get local change count: vault_id=%s, last_change_id=%v, error=%v", vault.ID, lastChangeID, err)
			return withError(err, true)
		}

		changeCount, err := s.appDeps.Client.GetRecordChangesCount(
			s.context.SelectedSot.Address,
			vault.ID,
			lastChangeID,
		)
		if err != nil {
			// log.Printf("[ListRecord] failed to get remote change count: vault_id=%s, last_change_id=%v, error=%v", vault.ID, lastChangeID, err)
			return withError(err, true)
		}

		totalChanges += changeCount.Count

		// log.Printf(
		// 	"[ListRecord] manual sync check completed: vault_id=%s, local_and_remote_changes=%d",
		// 	vault.ID,
		// 	totalChanges,
		// )

		return withError(nil, totalChanges > 0)

	default:
		// log.Printf(
		// 	"[ListRecord] no sync performed: unsupported sync mode, vault_id=%s, sync_mode=%v",
		// 	vault.ID,
		// 	s.context.SelectedSot.SyncMode,
		// )
	}

	return withError(nil, false)
}
