package dto

type CertificateResponse struct {
	Country      string
	Organization string
	CommonName   string
	Address      string
	Province     string
	Email        string
	SerialNumber string
	PostalCode   string
	Issuer       string
	Revoked      bool
	Valid        bool
	ValidFromTo  string
	Eku          string
}
