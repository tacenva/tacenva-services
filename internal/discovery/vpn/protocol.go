package vpn

import (
	"encoding/json"
	"fmt"
)

const (
	DiscoveryPort = 49154
	Magic         = "tacpassd-vpn-discovery"
	Version       = 1
)

type Request struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

type Response struct {
	Magic    string `json:"magic"`
	Version  int    `json:"version"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

func encodeRequest() ([]byte, error) {
	return json.Marshal(Request{
		Magic:   Magic,
		Version: Version,
	})
}

func decodeResponse(data []byte) (Response, error) {
	var response Response

	if err := json.Unmarshal(data, &response); err != nil {
		return response, err
	}

	if response.Magic != Magic {
		return response, fmt.Errorf("invalid discovery magic")
	}

	if response.Version != Version {
		return response, fmt.Errorf("unsupported discovery version")
	}

	if response.Hostname == "" {
		return response, fmt.Errorf("empty hostname")
	}

	if response.Port < 1 || response.Port > 65535 {
		return response, fmt.Errorf("invalid server port")
	}

	return response, nil
}
