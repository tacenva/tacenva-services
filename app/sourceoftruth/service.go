package sourceoftruth

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/config"
	coreEntity "github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/util/keyring"
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	appDeps           *app.Deps
	sotFile           *database.DatabaseFile
	authService       *auth.Service
	permissionService *permission.Service
}

func NewService(
	appDeps *app.Deps,
	authService *auth.Service,
	permissionService *permission.Service,
) *Service {
	return &Service{
		appDeps:           appDeps,
		authService:       authService,
		permissionService: permissionService,
	}
}

func (s *Service) Initialize(
	name string,
	hostname string,
) (string, *keyring.KeyPair, error) {
	_, keyPair, err := s.permissionService.Create(
		name,
		coreEntity.PrivilegeAdmin,
	)
	if err != nil {
		return "", nil, err
	}

	_, token, err := s.authService.Enroll(
		hostname,
		keyPair.PublicKey,
		coreEntity.UserStatusApproved,
	)
	if err != nil {
		return "", nil, err
	}

	return token, keyPair, nil
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
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}

		token, keyPair, err := s.Initialize(
			string(coreEntity.PrivilegeAdmin),
			hostname,
		)
		if err != nil {
			return err
		}

		_, err = s.sotFile.Insert(
			&entity.SourceOfTruth{
				ID:        s.appDeps.Config.SoTULID,
				Hostname:  hostname,
				Address:   "localhost",
				AuthToken: token,
				KeyPair:   *keyPair,
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) ChangePassword(
	currentPassword string,
	newPassword string,
) error {
	return s.sotFile.ChangePassword(
		currentPassword,
		newPassword,
	)
}

func normalizeAddress(address string) string {
	address = strings.TrimSpace(address)

	if address == "" {
		return ""
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
		u.Host = net.JoinHostPort(u.Hostname(), string(config.DefaultPort))
	}

	return u.String()
}

func (s *Service) Create(
	hostnameAlias string,
	address string,
	keypair keyring.KeyPair,
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
		api.EnrollRequest{
			Hostname:  hostname,
			PublicKey: keypair.PublicKey,
		},
	)
	if err != nil {
		return "", err
	}

	sotHostname := response.SoTHostname
	if hostnameAlias != "" {
		sotHostname = hostnameAlias
	}

	return s.sotFile.Insert(
		&entity.SourceOfTruth{
			Hostname:       sotHostname,
			Address:        address,
			AuthToken:      response.AuthToken,
			KeyPair:        keypair,
			TLSFingerprint: fingerprint,
			HashSync:       "",
			SyncMode:       syncMode,
		},
	)
}

func (s *Service) Update(
	updatedSoT *entity.SourceOfTruth,
) error {
	if s.sotFile == nil {
		return ErrForbidden
	}

	updatedSoT.Address = normalizeAddress(updatedSoT.Address)
	return s.sotFile.Update(updatedSoT)
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

func (s *Service) List() ([]entity.SourceOfTruth, error) {
	if s.sotFile == nil {
		return nil, ErrForbidden
	}

	var sotData []entity.SourceOfTruth

	if err := s.sotFile.FindAll(&sotData); err != nil {
		return nil, err
	}

	sort.Slice(sotData, func(i, j int) bool {
		iLocal := sotData[i].Address == "localhost"
		jLocal := sotData[j].Address == "localhost"

		if iLocal != jLocal {
			return iLocal
		}

		return strings.ToLower(sotData[i].Hostname) <
			strings.ToLower(sotData[j].Hostname)
	})

	return sotData, nil
}

func (s *Service) Del(
	sot *entity.SourceOfTruth,
) (*entity.SourceOfTruth, error) {
	if s.sotFile == nil {
		return nil, ErrForbidden
	}

	if sot == nil {
		return nil, errors.New("source of truth cannot be nil")
	}

	if sot.ID == "" {
		return nil, errors.New("source of truth id cannot be empty")
	}

	var stored entity.SourceOfTruth
	err := s.sotFile.Find(sot.ID, &stored)
	if err != nil {
		return nil, err
	}

	if stored.Address == "localhost" {
		return nil, errors.New("deleting localhost is prohibited")
	}

	oldData, err := s.sotFile.Delete(stored.ID)
	if err != nil {
		return nil, err
	}

	var deleted entity.SourceOfTruth
	if err := json.Unmarshal(oldData, &deleted); err != nil {
		return nil, err
	}

	return &deleted, nil
}
