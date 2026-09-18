package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

type Server struct {
	Name string
	Host string
	IP   net.IP
	Port int
}

func Discover(
	timeout time.Duration,
) ([]Server, error) {
	entries := make(chan *mdns.ServiceEntry)

	var servers []Server

	done := make(chan struct{})

	go func() {
		defer close(done)

		for entry := range entries {
			if entry == nil {
				continue
			}

			if !isTacpassd(entry.InfoFields) {
				continue
			}

			ip := entry.AddrV4

			if ip == nil {
				ip = entry.AddrV6
			}

			if ip == nil {
				continue
			}

			servers = append(
				servers,
				Server{
					Name: strings.TrimSuffix(
						entry.Name,
						".",
					),
					Host: strings.TrimSuffix(
						entry.Host,
						".",
					),
					IP:   ip,
					Port: entry.Port,
				},
			)
		}
	}()

	params := &mdns.QueryParam{
		Service: "_https._tcp",
		Domain:  "local",
		Timeout: timeout,
		Entries: entries,
	}

	if err := mdns.Query(params); err != nil {
		close(entries)
		<-done

		return nil, fmt.Errorf(
			"query mdns: %w",
			err,
		)
	}

	close(entries)
	<-done

	return servers, nil
}

func isTacpassd(
	info []string,
) bool {
	for _, value := range info {
		if value == "service=tacpassd" {
			return true
		}
	}

	return false
}
