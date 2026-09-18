package vpn

import (
	"encoding/json"
	"fmt"
)

const (
	DiscoveryPort = 49154

	Magic   = "tacpassd-vpn-discovery"
	Version = 1
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
		return Response{}, fmt.Errorf(
			"decode VPN discovery response: %w",
			err,
		)
	}

	if response.Magic != Magic {
		return Response{}, fmt.Errorf(
			"invalid discovery magic",
		)
	}

	if response.Version != Version {
		return Response{}, fmt.Errorf(
			"unsupported discovery version: %d",
			response.Version,
		)
	}

	if response.Hostname == "" {
		return Response{}, fmt.Errorf(
			"discovery response hostname is empty",
		)
	}

	if response.Port <= 0 || response.Port > 65535 {
		return Response{}, fmt.Errorf(
			"invalid discovery port: %d",
			response.Port,
		)
	}

	return response, nil
}
