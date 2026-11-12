package app

import (
	"fmt"
	"runtime"
	"strconv"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/config"
	"github.com/tacenva/tacenva-services/api"
	"github.com/tacenva/tacenva-services/app/server"
	"github.com/tacenva/tacenva-services/internal/discovery"
	"github.com/tacenva/tacenva-services/internal/discovery/mdns"
	"github.com/tacenva/tacenva-services/internal/discovery/vpn"
	tacpassapp "github.com/tacenva/tacpass-core/app"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Setup(dev bool) (*Deps, error) {
	cfg, err := config.LoadOrCreate(dev)
	if err != nil {
		return nil, err
	}

	tacenvaDB := database.New(cfg.BaseDir)

	sqliteDB, err := openSQLite(
		cfg.Path(config.AppDBFileName),
	)
	if err != nil {
		return nil, err
	}

	if _, err := sqliteDB.DB(); err != nil {
		return nil, fmt.Errorf(
			"get sqlite database: %w",
			err,
		)
	}

	if err := tacpassapp.Migrate(sqliteDB); err != nil {
		return nil, err
	}

	client := api.NewClient()

	serverService := setupDiscovery()

	deps := &Deps{
		Config:        cfg,
		AppDB:         tacenvaDB,
		SqliteDB:      sqliteDB,
		Client:        client,
		ServerService: serverService,
	}

	return deps, nil
}

func openSQLite(path string) (*gorm.DB, error) {
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

func vpnInterfaceNames() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"tun0",
			"tun1",
			"tap0",
			"tap1",
			"wg0",
			"wg1",
			"tailscale0",
		}

	case "windows":
		return []string{
			"OpenVPN Connect DCO Adapter",
			"Ethernet",
			"WireGuard Tunnel",
			"Tailscale",
			"ZeroTier One",
		}

	case "darwin":
		names := []string{
			"tun0",
			"tap0",
		}

		for i := 0; i <= 15; i++ {
			names = append(names, "utun"+strconv.Itoa(i))
		}

		return names
	}

	return nil
}

func setupDiscovery() *server.Service {
	discoverers := []discovery.Discoverer{
		mdns.NewDiscoverer(),
	}

	for _, name := range vpnInterfaceNames() {
		discoverers = append(
			discoverers,
			vpn.NewDiscoverer(name),
		)
	}

	return server.NewService(discoverers...)
}
