package api

import "github.com/tacenva/tacpass-core/contract"

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
