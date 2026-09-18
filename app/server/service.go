package server

import (
	"fmt"
	"sort"
	"time"

	"github.com/tacenva/tacenva-services/internal/discovery"
)

type Service struct {
	discoverers []discovery.Discoverer
}

func NewService(discoverers ...discovery.Discoverer) *Service {
	return &Service{
		discoverers: discoverers,
	}
}

func (s *Service) Discover(timeout time.Duration) ([]discovery.Server, error) {
	if len(s.discoverers) == 0 {
		return nil, fmt.Errorf("no server discovery providers configured")
	}

	type result struct {
		servers []discovery.Server
		err     error
	}

	results := make(chan result, len(s.discoverers))

	for _, discoverer := range s.discoverers {
		go func(d discovery.Discoverer) {
			fmt.Printf(
				"starting discovery provider: %T\n",
				d,
			)

			servers, err := d.Discover(timeout)

			if err != nil {
				fmt.Printf(
					"discovery provider %T error: %v\n",
					d,
					err,
				)
			} else {
				fmt.Printf(
					"discovery provider %T found %d server(s)\n",
					d,
					len(servers),
				)
			}

			results <- result{
				servers: servers,
				err:     err,
			}
		}(discoverer)
	}

	var all []discovery.Server
	var lastErr error

	for range s.discoverers {
		result := <-results

		if result.err != nil {
			lastErr = result.err
			continue
		}

		all = append(all, result.servers...)
	}

	all = deduplicate(all)

	sort.Slice(all, func(i, j int) bool {
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}

		return all[i].Port < all[j].Port
	})

	if len(all) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return all, nil
}

func deduplicate(servers []discovery.Server) []discovery.Server {
	seen := make(map[string]struct{})
	result := make([]discovery.Server, 0, len(servers))

	for _, server := range servers {
		key := fmt.Sprintf("%s:%d", server.Host, server.Port)

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, server)
	}

	return result
}
