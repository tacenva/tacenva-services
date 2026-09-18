package app

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/internal/discovery"
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

	if err := coreapp.Migrate(sqliteDB); err != nil {
		return nil, err
	}

	client := api.NewClient()

	deps := &Deps{
		Config:   cfg,
		AppDB:    tacenvaDB,
		SqliteDB: sqliteDB,
		Client:   client,
	}

	// Discovery tidak lagi memblok startup.
	go discoverServers(client)

	return deps, nil
}

func discoverServers(
	client *api.Client,
) {
	servers, err := discovery.Discover(
		3 * time.Second,
	)
	if err != nil {
		fmt.Printf(
			"mDNS discovery failed: %v\n",
			err,
		)
		return
	}

	for _, server := range servers {
		address := "https://" + net.JoinHostPort(
			server.Host,
			strconv.Itoa(server.Port),
		)

		dialAddress := net.JoinHostPort(
			server.IP.String(),
			strconv.Itoa(server.Port),
		)

		client.ConfigureDialAddress(
			address,
			dialAddress,
		)

		fmt.Printf(
			"mDNS endpoint: address=%q dial=%q\n",
			address,
			dialAddress,
		)
	}
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
