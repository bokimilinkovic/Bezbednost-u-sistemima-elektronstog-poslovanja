package dto

type CertificateRequest struct {
	Country              string `json:"country" validate:"min=2, max=20,regexp=^[a-zA-Z]*$"`
	Organization         string `json:"organization" validate="min=2, max=20,regexp=^[a-zA-Z]*$"`
	PostalCode           string `json:"postalcode" validate="regexp^[0-9]{1,6}$"`
	StreetAddress        string `json:"streetaddress" validate:"min=2, max=40"`
	Province             string `json:"province"`
	EmailAddress         string `json:"emailaddress"`
	Locality             string `json:"locality"`
	SerialNumber         string `json:"serialnumber"`
	StartsAt             string `json:"startsat"`
	EndsAt               string `json:"endsat"`
	CertificateAuthority string `json:"certificateauthority"`
	CommonName 			 string `json:"commonName"`
	Issuer               string `json:"issuer"`
	Eku                  string `json:"eku"`
}
