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

func (d *Discoverer) Discover(timeout time.Duration) ([]discovery.Server, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	port := d.Port
	if port <= 0 {
		port = DiscoveryPort
	}

	workerCount := d.Workers
	if workerCount <= 0 {
		workerCount = 32
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	iface, err := net.InterfaceByName(d.InterfaceName)
	if err != nil {
		// Interface kandidat memang boleh tidak tersedia di suatu OS.
		return nil, nil
	}

	if iface.Flags&net.FlagUp == 0 {
		return nil, nil
	}

	subnets, err := ipv4Subnets(iface)
	if err != nil {
		return nil, fmt.Errorf("get VPN subnets: %w", err)
	}

	if len(subnets) == 0 {
		return nil, nil
	}

	request, err := encodeRequest()
	if err != nil {
		return nil, fmt.Errorf("encode VPN discovery request: %w", err)
	}

	// Kumpulkan seluruh alamat target dan hilangkan duplikat.
	hostMap := make(map[string]net.IP)

	for _, subnet := range subnets {
		hosts, err := subnetHosts(subnet)
		if err != nil {
			continue
		}

		for _, ip := range hosts {
			hostMap[ip.String()] = ip
		}
	}

	hosts := make([]net.IP, 0, len(hostMap))
	for _, ip := range hostMap {
		hosts = append(hosts, ip)
	}

	if len(hosts) == 0 {
		return nil, nil
	}

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].String() < hosts[j].String()
	})

	jobs := make(chan net.IP)
	results := make(chan discovery.Server, len(hosts))

	var workers sync.WaitGroup

	count := workerCount
	if count > len(hosts) {
		count = len(hosts)
	}

	for i := 0; i < count; i++ {
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

					server, found := query(ctx, ip, port, request)
					if !found {
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

	go func() {
		defer close(jobs)

		for _, ip := range hosts {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	servers := make(map[string]discovery.Server)

	for server := range results {
		key := fmt.Sprintf("%s:%d", server.Host, server.Port)
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

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return discovery.Server{}, false
	}
	defer conn.Close()

	deadline := time.Now().Add(700 * time.Millisecond)

	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return discovery.Server{}, false
	}

	if _, err := conn.Write(request); err != nil {
		return discovery.Server{}, false
	}

	buffer := make([]byte, 4096)

	n, err := conn.Read(buffer)
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

func ipv4Subnets(iface *net.Interface) ([]*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf(
			"get addresses for interface %s: %w",
			iface.Name,
			err,
		)
	}

	var result []*net.IPNet

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}

		if len(ipNet.Mask) != net.IPv4len {
			continue
		}

		result = append(result, &net.IPNet{
			IP:   append(net.IP(nil), ip...),
			Mask: append(net.IPMask(nil), ipNet.Mask...),
		})
	}

	return result, nil
}

func subnetHosts(network *net.IPNet) ([]net.IP, error) {
	ip := network.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("network is not IPv4")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("network is not IPv4")
	}

	hostBits := bits - ones

	// /32 hanya memiliki satu alamat lokal.
	// Alamat peer tidak bisa ditebak dari subnet ini.
	if hostBits == 0 {
		return nil, nil
	}

	networkIP := ip.Mask(network.Mask)

	// RFC 3021: kedua alamat pada /31 dapat digunakan.
	if hostBits == 1 {
		var result []net.IP

		for i := uint32(0); i < 2; i++ {
			current := ipv4Add(networkIP, i)
			if !current.Equal(ip) {
				result = append(result, current)
			}
		}

		return result, nil
	}

	// Batasi maksimal /20 agar tidak memindai subnet terlalu besar.
	if hostBits > 12 {
		return nil, fmt.Errorf(
			"VPN subnet %s is too large to scan",
			network.String(),
		)
	}

	total := uint32(1) << hostBits
	result := make([]net.IP, 0, total-2)

	for i := uint32(1); i < total-1; i++ {
		current := ipv4Add(networkIP, i)

		if current.Equal(ip) {
			continue
		}

		result = append(result, current)
	}

	return result, nil
}

func ipv4Add(ip net.IP, n uint32) net.IP {
	ip = ip.To4()

	value := uint32(ip[0])<<24 |
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
