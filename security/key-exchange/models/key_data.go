package models

type KeyData struct {
	SignedPublicKey string `json:"signedPublicKey"`
	KeyId           string `json:"keyId,omitempty"`
	SignedKeyId     string `json:"signedKeyId"`
}
