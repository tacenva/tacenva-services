package discovery

import (
	"fmt"
	"net"
	"time"
)

type Source string

const (
	SourceMDNS Source = "mdns"
	SourceVPN  Source = "vpn"
)

type Server struct {
	Name   string
	Host   string
	IP     net.IP
	Port   int
	Source Source
}

type Discoverer interface {
	Discover(timeout time.Duration) ([]Server, error)
}

func (s Server) Address() string {
	return fmt.Sprintf(
		"https://%s:%d",
		s.Host,
		s.Port,
	)
}

func (s Server) DialAddress() string {
	return fmt.Sprintf(
		"%s:%d",
		s.IP.String(),
		s.Port,
	)
}
