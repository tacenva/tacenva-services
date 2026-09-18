package app

import (
	"fmt"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/api"
	coreapp "github.com/tacenva/tacpass-core/app"
	"github.com/tacenva/tacpass-core/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Setup(dev bool) (*Deps, error) {
	cfg, err := config.LoadOrCreate(dev)
	if err != nil {
		return nil, err
	}

	tacenvaDB := database.New(
		cfg.BaseDir,
	)

	sqliteDB, err := openSQLite(
		cfg.Path(config.AppDBFileName),
	)
	if err != nil {
		return nil, err
	}

	_, err = sqliteDB.DB()
	if err != nil {
		return nil, fmt.Errorf(
			"get sqlite database: %w",
			err,
		)
	}
	// defer sqlDB.Close()

	if err := coreapp.Migrate(sqliteDB); err != nil {
		return nil, err
	}

	client := api.NewClient()

	deps := Deps{
		Config:   cfg,
		AppDB:    tacenvaDB,
		SqliteDB: sqliteDB,
		Client:   client,
	}

	return &deps, nil
}

func openSQLite(
	path string,
) (*gorm.DB, error) {
	db, err := gorm.Open(
		sqlite.Open(path+"?_foreign_keys=on"),
		&gorm.Config{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open sqlite database: %w",
			err,
		)
	}

	return db, nil
}
