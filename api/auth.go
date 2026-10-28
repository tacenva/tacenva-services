package api

import (
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
)

func (c *Client) Enroll(
	address string,
	request tacenvacontract.EnrollRequest,
) (*tacenvacontract.EnrollResponse, error) {
	var response tacenvacontract.EnrollResponse

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
) (*tacenvacontract.AuthData, error) {
	var response tacenvacontract.AuthData

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
) (*tacenvacontract.GroupAssignment, error) {
	var groupAssignment tacenvacontract.GroupAssignment
	if err := c.Get(
		address,
		"/auth/group",
		&groupAssignment,
	); err != nil {
		return nil, err
	}

	return &groupAssignment, nil
}
