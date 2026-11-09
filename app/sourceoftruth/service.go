package sourceoftruth

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/accesscontrol"
	"github.com/tacenva/tacenva-core/auth"
	"github.com/tacenva/tacenva-core/config"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	"github.com/tacenva/tacenva-core/debug"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/util/keyring"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/entity"
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	appDeps              *app.Deps
	sotFile              *database.DatabaseFile
	authService          *auth.Service
	accessControlService *accesscontrol.Service
}

func NewService(
	appDeps *app.Deps,
	authService *auth.Service,
	accessControlService *accesscontrol.Service,
) *Service {
	return &Service{
		appDeps:              appDeps,
		authService:          authService,
		accessControlService: accessControlService,
	}
}

func (s *Service) Initialize() (response *tacenvacontract.EnrollResponse, keyPairOfUnit, keyPairOfGroup *keyring.KeyPair, err error) {
	ReplicaIdentity := s.appDeps.Config.Identity()
	keyPairOfUnit, keyPairOfGroup, err = s.accessControlService.Internal.InitAccess(s.appDeps.Config.SotID, "Tacenva")
	if err != nil {
		return nil, nil, nil, err
	}

	response, err = s.authService.Enroll(
		&tacenvacontract.EnrollRequest{
			ReplicaIdentity: ReplicaIdentity,
			PublicKey:       keyPairOfUnit.PublicKey,
		},
		s.appDeps.Config.SotID,
		tacenvaentity.UserStatusApproved,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return response, keyPairOfUnit, keyPairOfGroup, nil
}

func (s *Service) Access(
	masterPassword string,
) error {
	sotFile, err := s.appDeps.AppDB.File(
		"source-of-truth",
		masterPassword,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return err
	}

	s.sotFile = sotFile

	if s.sotFile.Count() == 0 {
		result, keyPairOfUnit, keyPairOfGroup, err := s.Initialize()
		if err != nil {
			return err
		}

		if err := s.sotFile.Insert(
			&entity.SourceOfTruth{
				ID:          s.appDeps.Config.SotID,
				SotIdentity: result.SotIdentity,
				Address:     "localhost",

				Auth: &entity.Auth{
					Token:               result.AuthToken,
					Status:              result.Status,
					Level:               result.AccessLevel,
					KeyPairOfAccessUnit: *keyPairOfUnit,
				},

				AccessGroup: &entity.AccessGroup{
					ID:      result.GroupAssignment.ID,
					KeyPair: keyPairOfGroup,
				},
			},
		).Error; err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) ChangePassword(
	currentPassword string,
	newPassword string,
) error {
	if err := s.sotFile.ChangePassword(
		currentPassword,
		newPassword,
	); err != nil {
		return err
	}

	var sotList []entity.SourceOfTruth

	if err := s.sotFile.FindAll(
		&sotList,
	).Error; err != nil {
		return err
	}

	for _, sot := range sotList {
		db := database.New(
			s.appDeps.Config.Path(
				config.NodeDirName,
				sot.ID,
				"vault",
			),
		)

		fileDB, err := db.File(
			"vault",
			currentPassword,
			database.FileModeOpen,
		)
		if err != nil {
			if errors.Is(
				err,
				database.ErrFileNotFound,
			) {
				continue
			}

			return err
		}

		if err := fileDB.ChangePassword(
			currentPassword,
			newPassword,
		); err != nil {
			return err
		}
	}

	return nil
}

func normalizeAddress(address string) string {
	address = strings.TrimSpace(address)

	if address == "" || address == "localhost" {
		return address
	}

	if !strings.HasPrefix(address, "https://") &&
		!strings.HasPrefix(address, "http://") {
		address = "https://" + address
	}

	u, err := url.Parse(address)
	if err != nil {
		return address
	}

	if u.Port() == "" {
		u.Host = net.JoinHostPort(
			u.Hostname(),
			strconv.Itoa(
				config.DefaultPort,
			),
		)
	}

	return u.String()
}

func (s *Service) uniqueSotIdentity(identity string) (string, error) {
	identity = strings.Join(strings.Fields(identity), " ")
	if identity == "" {
		return "", errors.New("sot identity cannot be empty")
	}

	normalized := strings.ToLower(identity)

	var existingSots []entity.SourceOfTruth

	err := s.sotFile.FindWhere(&existingSots, func(m map[string]any) bool {
		cur, ok := m["sot_identity"].(string)
		if !ok {
			return false
		}

		cur = strings.ToLower(strings.Join(strings.Fields(cur), " "))

		if cur == normalized {
			return true
		}

		prefix := normalized + " ("
		if !strings.HasPrefix(cur, prefix) || !strings.HasSuffix(cur, ")") {
			return false
		}

		suffix := strings.TrimSuffix(strings.TrimPrefix(cur, prefix), ")")
		n, err := strconv.Atoi(suffix)

		return err == nil && n >= 2
	}).Error
	if err != nil {
		return "", err
	}

	maxSuffix := 0

	for _, sot := range existingSots {
		cur := strings.ToLower(strings.Join(
			strings.Fields(sot.SotIdentity), " ",
		))

		if cur == normalized {
			maxSuffix = max(maxSuffix, 1)
			continue
		}

		prefix := normalized + " ("
		if !strings.HasPrefix(cur, prefix) || !strings.HasSuffix(cur, ")") {
			continue
		}

		suffix := strings.TrimSuffix(strings.TrimPrefix(cur, prefix), ")")
		n, err := strconv.Atoi(suffix)
		if err == nil && n >= 2 {
			maxSuffix = max(maxSuffix, n)
		}
	}

	if maxSuffix == 0 {
		return identity, nil
	}

	return fmt.Sprintf("%s (%d)", identity, maxSuffix+1), nil
}

func (s *Service) Create(
	identityAlias string,
	address string,
	keyPairOfAccessUnit keyring.KeyPair,
	syncMode entity.SyncMode,
) (string, error) {
	if s.sotFile == nil {
		return "", ErrForbidden
	}

	address = normalizeAddress(address)

	var fingerprint string

	s.appDeps.Client.ConfigureTLS(
		address,
		api.TLSConfig{
			Fingerprint: "",
			OnFirstTrust: func(newFingerprint string) error {
				fingerprint = newFingerprint
				return nil
			},
		},
	)

	response, err := s.appDeps.Client.Enroll(
		address,
		tacenvacontract.EnrollRequest{
			ReplicaIdentity: s.appDeps.Config.Identity(),
			PublicKey:       keyPairOfAccessUnit.PublicKey,
		},
	)
	if err != nil {
		return "", err
	}

	sotIdentity := response.SotIdentity

	if alias := strings.TrimSpace(identityAlias); alias != "" {
		sotIdentity = alias
	}

	sotIdentity, err = s.uniqueSotIdentity(sotIdentity)
	if err != nil {
		return "", err
	}

	newSot := entity.SourceOfTruth{
		SotIdentity: sotIdentity,
		Address:     address,
		SyncMode:    syncMode,

		Auth: &entity.Auth{
			Token:               response.AuthToken,
			Status:              response.Status,
			KeyPairOfAccessUnit: keyPairOfAccessUnit,
		},

		TLSFingerprint: &fingerprint,
	}

	if response.GroupAssignment != nil {
		var keyPairOfAccessGroup *keyring.KeyPair

		privateKeyOfAccessGroup, err := keyPairOfAccessUnit.Open(
			response.GroupAssignment.GroupKeyData.WrappedKey,
		)
		if err != nil {
			return "", err
		}

		keyPairOfAccessGroup = keyring.FromKeys(
			response.GroupAssignment.GroupKeyData.PublicKey,
			string(privateKeyOfAccessGroup),
		)

		newSot.AccessGroup = &entity.AccessGroup{
			ID:      response.GroupAssignment.ID,
			KeyPair: keyPairOfAccessGroup,
		}
	}

	sotResult := s.sotFile.Insert(&newSot)

	// debug.LogJSON("sot result", sotResult)

	if response.GroupAssignment != nil {
		err = s.accessControlService.SyncGroups(
			sotResult.ID,
			response.GroupAssignment.Items,
			response.GroupAssignment.LastSyncChange,
		)
		if err != nil {
			return "", err
		}
	}

	return sotResult.ID, sotResult.Error
}

func (s *Service) Update(
	updatedSoT *entity.SourceOfTruth,
) error {
	if s.sotFile == nil {
		return ErrForbidden
	}

	if updatedSoT == nil {
		return errors.New(
			"source of truth cannot be nil",
		)
	}

	updatedSoT.Address = normalizeAddress(
		updatedSoT.Address,
	)

	return s.sotFile.Update(
		updatedSoT,
	).Error
}

// ResetTLSFingerprint removes the stored TLS fingerprint
// from the Source of Truth.
//
// Once the fingerprint is cleared, the next HTTPS request will
// use the TOFU mechanism through OnFirstTrust, and the new
// fingerprint will be stored again by the caller.
//
// This method intentionally resides in the SourceOfTruth Service
// because the fingerprint is part of the persisted SoT state,
// rather than merely temporary HTTP client state.
func (s *Service) ResetTLSFingerprint(
	sot *entity.SourceOfTruth,
) error {
	if s.sotFile == nil {
		return ErrForbidden
	}

	if sot == nil {
		return errors.New(
			"source of truth cannot be nil",
		)
	}

	// Hapus fingerprint lama dari persisted SoT.
	sot.TLSFingerprint = nil

	// Persist state baru.
	if err := s.Update(sot); err != nil {
		return err
	}

	// Reset TLS state di API client juga.
	s.appDeps.Client.ConfigureTLS(
		sot.Address,
		api.TLSConfig{
			Fingerprint: "",

			OnFirstTrust: func(
				fingerprint string,
			) error {
				// Simpan fingerprint baru.
				sot.TLSFingerprint = &fingerprint

				return s.Update(sot)
			},
		},
	)

	return nil
}

func (s *Service) Get(
	id string,
) (*entity.SourceOfTruth, error) {
	if s.sotFile == nil {
		return nil, ErrForbidden
	}

	var sotData entity.SourceOfTruth

	err := s.sotFile.Find(
		id,
		&sotData,
	)
	if err != nil {
		return nil, err
	}

	return &sotData, nil
}

func (s *Service) List() (
	[]entity.SourceOfTruth,
	error,
) {
	if s.sotFile == nil {
		return nil, ErrForbidden
	}

	var sotData []entity.SourceOfTruth

	if err := s.sotFile.FindAll(
		&sotData,
	).Error; err != nil {
		return nil, err
	}

	sort.Slice(
		sotData,
		func(i, j int) bool {
			iLocal := sotData[i].Address == "localhost"
			jLocal := sotData[j].Address == "localhost"

			if iLocal != jLocal {
				return iLocal
			}

			return strings.ToLower(
				sotData[i].SotIdentity,
			) < strings.ToLower(
				sotData[j].SotIdentity,
			)
		},
	)

	// debug.LogJSON("sot list", sotData)

	return sotData, nil
}

func (s *Service) Delete(
	sot *entity.SourceOfTruth,
) error {
	if s.sotFile == nil {
		return ErrForbidden
	}

	if sot == nil {
		return errors.New(
			"source of truth cannot be nil",
		)
	}

	if sot.ID == "" {
		return errors.New(
			"source of truth id cannot be empty",
		)
	}

	var stored entity.SourceOfTruth

	err := s.sotFile.Find(
		sot.ID,
		&stored,
	)
	if err != nil {
		return err
	}

	if stored.Address == "localhost" {
		return errors.New(
			"deleting localhost is prohibited",
		)
	}

	if err := s.accessControlService.Destroy(sot.ID); err != nil {
		return err
	}

	nodeDir := s.appDeps.Config.Path(
		config.NodeDirName,
		sot.ID,
	)

	if err := os.RemoveAll(nodeDir); err != nil {
		return err
	}

	if err := s.sotFile.Delete(
		stored.ID,
	).Error; err != nil {
		return err
	}

	return nil
}

func (s *Service) CheckStatus(
	sot *entity.SourceOfTruth,
) error {
	accessGroupLastChangeID := ""
	if sot.Auth.Level.AllowsWrite() {
		latestSyncChange, err := s.accessControlService.GetLastSyncChange(sot.ID)
		if err != nil {
			return err
		}

		if latestSyncChange != nil {
			accessGroupLastChangeID = latestSyncChange.ID
		}
	}

	authData, err := s.appDeps.Client.GetAuthData(sot.Address, accessGroupLastChangeID)
	if err != nil {
		return err
	}

	changed := false

	if sot.Auth.Level != authData.AccessLevel {
		sot.Auth.Level = authData.AccessLevel
		changed = true
	}

	if sot.Auth.Status != authData.Status {
		sot.Auth.Status = authData.Status
		changed = true
	}

	if authData.GroupAssignment != nil &&
		(sot.AccessGroup == nil ||
			sot.AccessGroup.ID != authData.GroupAssignment.ID) {

		if sot.AccessGroup == nil {
			sot.AccessGroup = &entity.AccessGroup{}
		}

		sot.AccessGroup.ID = authData.GroupAssignment.ID

		unwrappedGroupPrivateKey, err := sot.Auth.KeyPairOfAccessUnit.Open(
			authData.GroupAssignment.GroupKeyData.WrappedKey,
		)
		debug.LogJSON("auth data", authData)
		if err != nil {
			log.Println(err)
			return err
		}

		sot.AccessGroup.KeyPair = keyring.FromKeys(
			authData.GroupAssignment.GroupKeyData.PublicKey,
			string(unwrappedGroupPrivateKey),
		)

		if err := s.accessControlService.SyncGroups(
			sot.ID,
			authData.GroupAssignment.Items,
			authData.GroupAssignment.LastSyncChange,
		); err != nil {
			return err
		}

		changed = true
	}

	if !changed {
		return nil
	}

	return s.sotFile.Update(sot).Error
}
