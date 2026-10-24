package vault

import (
	"errors"

	"github.com/tacenva/database"
	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/contract"
	coreEntity "github.com/tacenva/tacpass-core/entity"
)

func (s *Service) AppendRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
	wrappedKey string,
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

	vaultFile, err := s.openRecordFile(vault, wrappedKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()

	var (
		syncChangeID string
		recordID     string
	)

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return nil, err
		}

		err = s.vaultrecordService.CreateOnSot(
			authUser,
			vaultDir,
			vault.ID,
			&recordID,
			[]byte(encrypted),
			s.context.SelectedSot.ID,
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return nil, err
		}
	} else {
		err = s.vaultrecordService.CreateOnReplica(
			vaultDir,
			vault.ID,
			&recordID,
			[]byte(encrypted),
			s.context.SelectedSot.ID,
			&syncChangeID,
			"",
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
	wrappedKey string,
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

	vaultFile, err := s.openRecordFile(vault, wrappedKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()

	var syncChangeID string

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return nil, err
		}

		err = s.vaultrecordService.UpdateOnSot(
			authUser,
			vaultDir,
			vault.ID,
			record.ID,
			[]byte(encrypted),
			s.context.SelectedSot.ID,
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return nil, err
		}
	} else {
		err = s.vaultrecordService.UpdateOnReplica(
			vaultDir,
			vault.ID,
			record.ID,
			[]byte(encrypted),
			s.context.SelectedSot.ID,
			&syncChangeID,
			"",
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

	vaultDir := s.vaultDir()

	var syncChangeID string
	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return err
		}

		err = s.vaultrecordService.DeleteOnSot(
			authUser,
			vaultDir,
			vault.ID,
			record.ID,
			s.context.SelectedSot.ID,
			&syncChangeID,
			s.context.SelectedSot.Hostname,
		)
		if err != nil {
			return err
		}
	} else {
		err := s.vaultrecordService.DeleteOnReplica(
			vaultDir,
			vault.ID,
			record.ID,
			s.context.SelectedSot.ID,
			&syncChangeID,
			s.context.SelectedSot.Hostname,
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
	vaultDir := s.vaultDir()

	lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
		s.context.SelectedSot.ID,
		vault.ID,
	)
	if err != nil {
		return err
	}

	localChanges, err := s.getLocalRecordChanges(
		vaultDir,
		vault.ID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	clientChanges, clientChangeTotal, err := s.getClientRecordChanges(
		vault.ID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	err = s.appDeps.Client.SyncRecords(
		s.context.SelectedSot.Address,
		vault.ID,
		lastChangeID,
		int(clientChangeTotal.Count),
		localChanges,
	)
	if err != nil {
		return err
	}

	if err := s.vaultrecordService.SyncOnReplica(
		vaultDir,
		s.context.SelectedSot.ID,
		vault.ID,
		clientChanges,
		localChanges,
	); err != nil {
		return err
	}

	return s.vaultrecordService.SetSyncStateToBeLastest(
		s.context.SelectedSot.ID,
		vault.ID,
	)
}

func (s *Service) getLocalRecordChanges(
	vaultDir string,
	vaultID string,
	lastChangeID string,
) (*contract.PendingVaultRecordChange, error) {
	changeCount, err := s.vaultrecordService.GetChangeCount(
		s.context.SelectedSot.ID,
		vaultID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if changeCount == 0 {
		return nil, nil
	}

	return s.vaultrecordService.GetChangesAfter(
		vaultDir,
		vaultID,
		s.context.SelectedSot.ID,
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

func (s *Service) ListRecord(
	vault *coreEntity.Vault,
	wrappedKey string,
) ([]coreEntity.VaultRecord, bool, error) {
	if vault == nil {
		return nil, false, errors.New(
			"vault cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, false, errors.New(
			"vault id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, false, errors.New(
			"context is nil",
		)
	}

	if s.context.SelectedSot == nil {
		return nil, false, errors.New(
			"selected source of truth is nil",
		)
	}

	vaultDir := s.vaultDir()
	vaultKey, err := s.context.SelectedSot.KeyPair.Open(wrappedKey)

	records, err := s.vaultrecordService.List(
		vaultDir,
		vault.ID,
		string(vaultKey),
	)

	if err != nil {
		if err == database.ErrFileNotFound && s.context.IsRemote {
			recordBlob, err := s.appDeps.Client.GetRecordBlob(
				s.context.SelectedSot.Address,
				vault.ID,
			)
			if err != nil {
				return nil, false, err
			}

			db := database.New(vaultDir)
			err = db.Write(vault.ID, recordBlob)
			if err != nil {
				return nil, false, err
			}

			records, err = s.vaultrecordService.List(
				vaultDir,
				vault.ID,
				string(vaultKey),
			)
			if err != nil {
				return nil, false, err
			}
		} else {
			return nil, false, err
		}
	}

	if !s.context.IsRemote {
		return records, false, nil
	}

	if !s.appDeps.Client.IsReachable() {
		return records, false, nil
	}

	switch s.context.SelectedSot.SyncMode {
	case operationsEntity.SyncModeAuto:
		if err := s.SyncRecord(vault); err != nil {
			return records, true, err
		}

		records, err = s.vaultrecordService.List(
			vaultDir,
			vault.ID,
			string(vaultKey),
		)
		if err != nil {
			return nil, false, err
		}

		return records, false, nil

	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
			s.context.SelectedSot.ID,
			vault.ID,
		)
		if err != nil {
			return records, false, err
		}

		totalChanges, err := s.vaultrecordService.GetChangeCount(
			s.context.SelectedSot.ID,
			vault.ID,
			lastChangeID,
		)
		if err != nil {
			return records, false, err
		}

		changeCount, err := s.appDeps.Client.GetRecordChangesCount(
			s.context.SelectedSot.Address,
			vault.ID,
			lastChangeID,
		)
		if err != nil {
			return records, false, err
		}

		totalChanges += changeCount.Count

		return records, totalChanges > 0, nil
	}

	return records, false, nil
}
