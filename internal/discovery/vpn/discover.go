package vpn

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tacenva/tacenva-services/internal/discovery"
)

type Discoverer struct {
	InterfaceName string
	Port          int
	Workers       int
}

func NewDiscoverer(interfaceName string) *Discoverer {
	return &Discoverer{
		InterfaceName: interfaceName,
		Port:          DiscoveryPort,
		Workers:       32,
	}
}

func (d *Discoverer) Discover(
	timeout time.Duration,
) ([]discovery.Server, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	if d.Port <= 0 {
		d.Port = DiscoveryPort
	}

	if d.Workers <= 0 {
		d.Workers = 32
	}

	iface, err := net.InterfaceByName(d.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf(
			"find VPN interface %s: %w",
			d.InterfaceName,
			err,
		)
	}

	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf(
			"VPN interface %s is down",
			d.InterfaceName,
		)
	}

	subnets, err := ipv4Subnets(iface)
	if err != nil {
		return nil, err
	}

	if len(subnets) == 0 {
		return nil, fmt.Errorf(
			"no IPv4 subnet found on %s",
			d.InterfaceName,
		)
	}

	request, err := encodeRequest()
	if err != nil {
		return nil, fmt.Errorf(
			"encode VPN discovery request: %w",
			err,
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeout,
	)
	defer cancel()

	results := make(chan discovery.Server, 64)

	var workers sync.WaitGroup

	for _, subnet := range subnets {
		hosts, err := subnetHosts(subnet)
		if err != nil {
			continue
		}

		if len(hosts) == 0 {
			continue
		}

		jobs := make(chan net.IP)

		workerCount := d.Workers
		if workerCount > len(hosts) {
			workerCount = len(hosts)
		}

		for i := 0; i < workerCount; i++ {
			workers.Add(1)

			go func() {
				defer workers.Done()

				for {
					select {
					case <-ctx.Done():
						return

					case ip, ok := <-jobs:
						if !ok {
							return
						}

						server, ok := query(
							ctx,
							ip,
							d.Port,
							request,
						)

						if !ok {
							continue
						}

						select {
						case results <- server:
						case <-ctx.Done():
							return
						}
					}
				}
			}()
		}

	sendLoop:
		for _, ip := range hosts {
			select {
			case jobs <- ip:

			case <-ctx.Done():
				break sendLoop
			}
		}

		close(jobs)
	}

	go func() {
		workers.Wait()
		close(results)
	}()

	servers := make(map[string]discovery.Server)

	for server := range results {
		key := fmt.Sprintf(
			"%s:%d",
			server.Host,
			server.Port,
		)

		servers[key] = server
	}

	result := make([]discovery.Server, 0, len(servers))

	for _, server := range servers {
		result = append(result, server)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}

		return result[i].Port < result[j].Port
	})

	return result, nil
}

func query(
	ctx context.Context,
	ip net.IP,
	port int,
	request []byte,
) (discovery.Server, bool) {
	addr := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	conn, err := net.DialUDP(
		"udp4",
		nil,
		addr,
	)
	if err != nil {
		return discovery.Server{}, false
	}

	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return discovery.Server{}, false
		}
	} else {
		if err := conn.SetDeadline(
			time.Now().Add(500 * time.Millisecond),
		); err != nil {
			return discovery.Server{}, false
		}
	}

	_, err = conn.Write(request)
	if err != nil {
		return discovery.Server{}, false
	}

	buffer := make([]byte, 4096)

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return discovery.Server{}, false
	}

	response, err := decodeResponse(buffer[:n])
	if err != nil {
		return discovery.Server{}, false
	}

	return discovery.Server{
		Name:   response.Hostname,
		Host:   response.Hostname,
		IP:     append(net.IP(nil), ip...),
		Port:   response.Port,
		Source: discovery.SourceVPN,
	}, true
}

func ipv4Subnets(
	iface *net.Interface,
) ([]*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf(
			"get addresses for %s: %w",
			iface.Name,
			err,
		)
	}

	var result []*net.IPNet

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipnet.IP.To4()
		if ip == nil {
			continue
		}

		mask := ipnet.Mask
		if len(mask) != net.IPv4len {
			continue
		}

		result = append(result, &net.IPNet{
			IP:   ip,
			Mask: mask,
		})
	}

	return result, nil
}

func subnetHosts(
	network *net.IPNet,
) ([]net.IP, error) {
	ip := network.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf(
			"network is not IPv4",
		)
	}

	ones, bits := network.Mask.Size()

	if bits != 32 {
		return nil, fmt.Errorf(
			"network is not IPv4",
		)
	}

	hostBits := bits - ones

	if hostBits <= 1 {
		return nil, nil
	}

	// 4096 alamat adalah batas maksimum scanning.
	// Artinya hostBits maksimal 12.
	if hostBits > 12 {
		return nil, fmt.Errorf(
			"VPN subnet %s is too large to scan",
			network.String(),
		)
	}

	total := uint32(1) << hostBits

	networkIP := ip.Mask(network.Mask)

	result := make([]net.IP, 0, total-2)

	for i := uint32(1); i < total-1; i++ {
		current := ipv4Add(networkIP, i)

		// Jangan query IP sendiri.
		if current.Equal(ip) {
			continue
		}

		result = append(result, current)
	}

	return result, nil
}

func ipv4Add(
	ip net.IP,
	n uint32,
) net.IP {
	value :=
		uint32(ip[0])<<24 |
			uint32(ip[1])<<16 |
			uint32(ip[2])<<8 |
			uint32(ip[3])

	value += n

	return net.IPv4(
		byte(value>>24),
		byte(value>>16),
		byte(value>>8),
		byte(value),
	).To4()
}
