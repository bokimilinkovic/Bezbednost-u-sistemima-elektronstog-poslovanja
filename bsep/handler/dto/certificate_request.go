package dto

type CertificateRequest struct {
	Country              string `json:"country"`
	Organization         string `json:"organization"`
	PostalCode           string `json:"postalcode"`
	StreetAddress        string `json:"streetaddress"`
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
