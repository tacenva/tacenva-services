package app

import (
	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/config"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app/server"
	operationentity "github.com/tacenva/tacenva-services/entity"
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
	SelectedSot    *operationentity.SourceOfTruth
	AuthorizedUser *tacenvaentity.User
	NodeDB         *database.DB
	IsRemote       bool
}
