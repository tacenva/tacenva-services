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

func (c *Client) GetAuthData(
	address string,
) (*tacenvacontract.AuthData, error) {
	var response tacenvacontract.AuthData

	if err := c.Get(
		address,
		"/auth/",
		&response,
	); err != nil {
		return nil, err
	}

	return &response, nil
}
