package models

type KeyExchangeResponse struct {
	PublicKey        string `json:"publicKey,omitempty"`
	EncryptedKeyData string `json:"encryptedKeyData,omitempty"`
	SharedKey        string `json:"sharedKey,omitempty"`
}
