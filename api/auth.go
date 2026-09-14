package api

type EnrollRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

type EnrollResponse struct {
	Status      string `json:"status"`
	AuthToken   string `json:"auth_token"`
	SoTHostname string `json:"sot_hostname"`
}

func (c *Client) Enroll(
	address string,
	request EnrollRequest,
) (*EnrollResponse, error) {
	var response EnrollResponse

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

type LoginRequest struct {
	PublicKey string `json:"public_key"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func (c *Client) Login(
	address string,
	request LoginRequest,
) (*LoginResponse, error) {
	var response LoginResponse

	if err := c.PostPublic(
		address,
		"/auth/login",
		request,
		&response,
	); err != nil {
		return nil, err
	}

	c.SetToken(response.Token)

	return &response, nil
}

func (c *Client) Logout() {
	c.ClearToken()
}
