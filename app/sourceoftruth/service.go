package sourceoftruth

import (
	"encoding/json"
	"errors"
	"fmt"
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
	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil, nil, err
	}

	keyPairOfUnit, keyPairOfGroup, err = s.accessControlService.Internal.InitAccess(s.appDeps.Config.SotID)
	if err != nil {
		return nil, nil, nil, err
	}

	response, err = s.authService.Enroll(
		&tacenvacontract.EnrollRequest{
			Hostname:  hostname,
			PublicKey: keyPairOfUnit.PublicKey,
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
				ID:       s.appDeps.Config.SotID,
				Hostname: result.SotHostname,
				Address:  "localhost",

				Auth: &entity.Auth{
					Token:               result.AuthToken,
					Status:              result.Status,
					Level:               result.AccessLevel,
					KeyPairOfAccessUnit: *keyPairOfUnit,
				},

				AccessGroup: &entity.AccessGroup{
					ID:      result.GroupAssignment.ID,
					KeyPair: *keyPairOfGroup,
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

			fmt.Print(err)

			return err
		}

		if err := fileDB.ChangePassword(
			currentPassword,
			newPassword,
		); err != nil {
			fmt.Print(err)

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

func (s *Service) Create(
	hostnameAlias string,
	address string,
	keyPairOfAccessUnit keyring.KeyPair,
	syncMode entity.SyncMode,
) (string, error) {
	if s.sotFile == nil {
		return "", ErrForbidden
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	address = normalizeAddress(address)

	var fingerprint string

	s.appDeps.Client.ConfigureTLS(
		address,
		api.TLSConfig{
			Fingerprint: "",

			OnFirstTrust: func(
				newFingerprint string,
			) error {
				fingerprint = newFingerprint

				return nil
			},
		},
	)

	response, err := s.appDeps.Client.Enroll(
		address,
		tacenvacontract.EnrollRequest{
			Hostname:  hostname,
			PublicKey: keyPairOfAccessUnit.PublicKey,
		},
	)
	if err != nil {
		return "", err
	}

	sotHostname := response.SotHostname

	if hostnameAlias != "" {
		sotHostname = hostnameAlias
	}

	baseHostname := sotHostname

	var existingSots []entity.SourceOfTruth
	err = s.sotFile.FindWhere(&existingSots, func(m map[string]any) bool {
		hostname, ok := m["Hostname"].(string)
		if !ok {
			return false
		}

		if hostname == baseHostname {
			return true
		}

		prefix := baseHostname + "-"
		if !strings.HasPrefix(hostname, prefix) {
			return false
		}

		suffix := strings.TrimPrefix(hostname, prefix)
		_, err := strconv.Atoi(suffix)
		return err == nil
	}).Error
	if err != nil {
		return "", err
	}

	used := make(map[int]struct{}, len(existingSots))
	hostnameExists := false

	for _, sot := range existingSots {
		if sot.Hostname == baseHostname {
			hostnameExists = true
			continue
		}

		suffix := strings.TrimPrefix(sot.Hostname, baseHostname+"-")
		if n, err := strconv.Atoi(suffix); err == nil && n > 0 {
			used[n] = struct{}{}
		}
	}

	if hostnameExists {
		for i := 1; ; i++ {
			if _, exists := used[i]; !exists {
				sotHostname = fmt.Sprintf("%s-%d", baseHostname, i)
				break
			}
		}
	}

	newSot := entity.SourceOfTruth{
		Hostname: sotHostname,
		Address:  address,
		SyncMode: syncMode,

		Auth: &entity.Auth{
			Token:               response.AuthToken,
			Status:              response.Status,
			KeyPairOfAccessUnit: keyPairOfAccessUnit,
		},

		TLSFingerprint: &fingerprint,
	}

	if response.GroupAssignment != nil {
		privateKeyOfAccessGroup, err := keyPairOfAccessUnit.Open(response.GroupAssignment.WrappedPrivateKey)
		if err != nil {
			return "", err
		}

		newSot.AccessGroup = &entity.AccessGroup{
			ID: response.GroupAssignment.ID,
			KeyPair: *keyring.FromKeys(
				response.GroupAssignment.PublicKey,
				string(privateKeyOfAccessGroup),
			),
		}
	}

	sotResult := s.sotFile.Insert(&newSot)

	if response.GroupAssignment != nil {
		err = s.accessControlService.SyncGroups(sotResult.ID, response.GroupAssignment.Items)
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
				sotData[i].Hostname,
			) < strings.ToLower(
				sotData[j].Hostname,
			)
		},
	)

	jsonData, err := json.MarshalIndent(sotData, "", "  ")
	if err != nil {
		fmt.Println("Gagal marshal JSON:", err)
	} else {
		fmt.Println(string(jsonData))
	}

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

	return s.sotFile.Delete(
		stored.ID,
	).Error
}

func (s *Service) CheckStatus(
	sot *entity.SourceOfTruth,
) error {
	authData, err := s.appDeps.Client.GetAuthData(sot.Address)
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

	debug.LogJSON("authdata", authData)
	debug.LogJSON("sot", sot)

	if authData.GroupAssignment != nil &&
		(sot.AccessGroup == nil ||
			sot.AccessGroup.ID != authData.GroupAssignment.ID) {

		if sot.AccessGroup == nil {
			sot.AccessGroup = &entity.AccessGroup{}
		}

		sot.AccessGroup.ID = authData.GroupAssignment.ID

		if err := s.accessControlService.SyncGroups(
			sot.ID,
			authData.GroupAssignment.Items,
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
