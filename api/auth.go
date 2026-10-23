package api

import (
	"github.com/tacenva/tacpass-core/contract"
)

func (c *Client) Enroll(
	address string,
	request contract.EnrollRequest,
) (*contract.EnrollResponse, error) {
	var response contract.EnrollResponse

	if err := c.PostPublic(
		address,
		"/auth/enroll",
		request,
		&response,
	); err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) CheckStatus(
	address string,
) (*contract.AuthData, error) {
	var response contract.AuthData

	if err := c.Get(
		address,
		"/auth/status",
		&response,
	); err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GroupAssignment(
	address string,
) (*contract.GroupAssignment, error) {
	var groupAssignment contract.GroupAssignment
	if err := c.Get(
		address,
		"/auth/group",
		&groupAssignment,
	); err != nil {
		return nil, err
	}

	return &groupAssignment, nil
}
