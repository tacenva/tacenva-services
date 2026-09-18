package app

import (
	"fmt"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app/server"
	"github.com/tacenva/tacenva-services/internal/discovery/mdns"
	"github.com/tacenva/tacenva-services/internal/discovery/vpn"
	coreapp "github.com/tacenva/tacpass-core/app"
	"github.com/tacenva/tacpass-core/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Setup(dev bool) (*Deps, error) {
	fmt.Println("setting up tacenva-services...")

	cfg, err := config.LoadOrCreate(dev)
	if err != nil {
		return nil, err
	}

	fmt.Println("config loaded")

	tacenvaDB := database.New(cfg.BaseDir)
	fmt.Println("application database initialized")

	sqliteDB, err := openSQLite(cfg.Path(config.AppDBFileName))
	if err != nil {
		return nil, err
	}

	if _, err := sqliteDB.DB(); err != nil {
		return nil, fmt.Errorf("get sqlite database: %w", err)
	}

	fmt.Println("sqlite database opened")

	if err := coreapp.Migrate(sqliteDB); err != nil {
		return nil, err
	}

	fmt.Println("database migration completed")

	client := api.NewClient()
	fmt.Println("API client initialized")

	mdnsDiscoverer := mdns.NewDiscoverer()
	fmt.Println("mDNS discoverer initialized")

	vpnDiscoverer := vpn.NewDiscoverer("tun0")
	fmt.Println("VPN discoverer initialized: interface=tun0")

	serverService := server.NewService(
		mdnsDiscoverer,
		vpnDiscoverer,
	)

	fmt.Println("server discovery service initialized")

	deps := &Deps{
		Config:        cfg,
		AppDB:         tacenvaDB,
		SqliteDB:      sqliteDB,
		Client:        client,
		ServerService: serverService,
	}

	fmt.Println("tacenva-services setup completed")

	return deps, nil
}

func openSQLite(path string) (*gorm.DB, error) {
	db, err := gorm.Open(
		sqlite.Open(path+"?_foreign_keys=on"),
		&gorm.Config{},
	)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	return db, nil
}
