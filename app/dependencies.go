package app

import (
	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app/server"
	"github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/config"
	"gorm.io/gorm"
)

type Deps struct {
	Config   *config.Config
	AppDB    *database.DB
	SqliteDB *gorm.DB
	Client   *api.Client

	ServerService *server.Service
}
type Context struct {
	SelectedSoT *entity.SourceOfTruth
	NodeDB      *database.DB
	IsRemote    bool
}
