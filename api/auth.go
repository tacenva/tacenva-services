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
	accessGroupLastChangeID string,
) (*tacenvacontract.AuthDataResp, error) {
	request := tacenvacontract.AuthDataReq{
		AccessGroupLastChangeID: accessGroupLastChangeID,
	}

	var response tacenvacontract.AuthDataResp

	if err := c.Query(
		address,
		"/auth/",
		request,
		&response,
	); err != nil {
		return nil, err
	}

	return &response, nil
}
