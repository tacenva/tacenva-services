package mdns

import (
	"fmt"
	"net"
	"strings"
	"time"

	hashicorpmdns "github.com/hashicorp/mdns"

	"github.com/tacenva/tacenva-services/internal/discovery"
)

type Discoverer struct{}

func NewDiscoverer() *Discoverer {
	return &Discoverer{}
}

func (d *Discoverer) Discover(
	timeout time.Duration,
) ([]discovery.Server, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	entries := make(chan *hashicorpmdns.ServiceEntry)

	resultCh := make(chan discovery.Server, 32)

	go func() {
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

			host := strings.TrimSuffix(
				entry.Host,
				".",
			)

			name := strings.TrimSuffix(
				entry.Name,
				".",
			)

			resultCh <- discovery.Server{
				Name:   name,
				Host:   host,
				IP:     append(net.IP(nil), ip...),
				Port:   entry.Port,
				Source: discovery.SourceMDNS,
			}
		}

		close(resultCh)
	}()

	params := &hashicorpmdns.QueryParam{
		Service: "_https._tcp",
		Domain:  "local",
		Timeout: timeout,
		Entries: entries,
	}

	if err := hashicorpmdns.Query(params); err != nil {
		close(entries)

		for range resultCh {
		}

		return nil, fmt.Errorf(
			"query mDNS: %w",
			err,
		)
	}

	close(entries)

	var servers []discovery.Server

	for server := range resultCh {
		servers = append(servers, server)
	}

	return servers, nil
}

func isTacpassd(fields []string) bool {
	for _, field := range fields {
		field = strings.TrimSpace(field)

		if field == "service=tacpassd" {
			return true
		}
	}

	return false
}
