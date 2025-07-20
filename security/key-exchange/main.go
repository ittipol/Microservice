package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"key-exchange/database"
	"key-exchange/models"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func main() {

	var c Config
	c.loadConfig("config.yaml")

	rdb := initRedisConnection(c.RedisConfig)
	// rdb := initRedisClusterConnection()

	e := echo.New()
	// Debug mode
	e.Debug = true

	e.GET("/health", func(c echo.Context) error {
		fmt.Println("Test service, OK")
		return c.String(http.StatusOK, "Test service, OK")
	})

	e.POST("/key-exchange", func(c echo.Context) error {

		headers := c.Request().Header

		for i, v := range headers {
			fmt.Printf("[Header] %v --> %v\n", i, v)
		}

		clientPublicKeyHex := c.Request().Header.Get("public-key")

		fmt.Printf(">>>>> [Header] clientPublicKeyHex --> [ %v ]\n", clientPublicKeyHex)

		if clientPublicKeyHex == "" {
			return echo.NewHTTPError(http.StatusBadRequest, errors.New("clientPublicKey not found"))
		}

		byteArray, err := hex.DecodeString(clientPublicKeyHex)
		if err != nil {
			log.Printf("Error decoding hex string: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		clientPublicKey, err := generatePublicKeyFromByte(byteArray)
		if err != nil {
			log.Printf("Error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		serverPrivateKey, serverPublicKey, err := generateKeyPair()
		if err != nil {
			log.Printf("Error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		serverSecretKey := deriveSharedSecret(serverPrivateKey, clientPublicKey)

		keyId := generateKeyId()

		fmt.Printf("key-id: %s\n", keyId)

		keyData := models.KeyData{
			SignedPublicKey: "", // ECDSA
			KeyId:           keyId,
			SignedKeyId:     "", // JWTWithEC256
		}

		jsonData, err := json.Marshal(keyData)
		if err != nil {
			log.Printf("Error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		jsonString := string(jsonData)
		cipherText := aesGcmModeEncrypt([]byte(jsonString), serverSecretKey)

		serverSecretKeyBase64 := base64.StdEncoding.EncodeToString(serverSecretKey)

		response := models.KeyExchangeResponse{
			PublicKey:        hex.EncodeToString(serverPublicKey.Bytes()),
			EncryptedKeyData: cipherText,
			SharedKey:        serverSecretKeyBase64,
		}

		err = rdb.Set(context.Background(), keyId, serverSecretKeyBase64, 100*time.Minute).Err()
		if err != nil {
			log.Printf("Error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		return c.JSON(http.StatusOK, response)
	})

	// e.GET("/header", func(c echo.Context) error {

	// 	// header := c.Request().Header.Get("Authorization")

	// 	headers := c.Request().Header

	// 	for i, v := range headers {
	// 		fmt.Printf("%v --> %v\n", i, v)
	// 	}

	// 	return c.String(http.StatusOK, fmt.Sprintf("Headers: %v", headers))
	// })

	e.GET("/body", func(c echo.Context) error {

		fmt.Println("Test request body")

		json_map := make(map[string]interface{})
		if err := json.NewDecoder(c.Request().Body).Decode(&json_map); err != nil {
			log.Printf("Error: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		return c.String(http.StatusOK, fmt.Sprintf("body: %v", json_map))
	})

	e.GET("/json", func(c echo.Context) error {

		fmt.Println("Test json")

		response := models.KeyExchangeResponse{
			PublicKey:        "aaaa",
			EncryptedKeyData: "bbbb",
			SharedKey:        "cccc",
		}

		return c.JSON(http.StatusOK, response)
	})

	// e.GET("/cache/set", func(c echo.Context) error {

	// 	key := "cache_test"

	// 	fmt.Println("call /cache/set")

	// 	err := rdb.Set(context.Background(), key, "test", 10*time.Minute).Err()
	// 	if err != nil {
	// 		return echo.NewHTTPError(http.StatusInternalServerError, err)
	// 	}
	// 	return c.String(http.StatusOK, fmt.Sprintf("Cache set, %v", key))
	// })

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", c.AppPort)))
}

func generateKeyPair() (privKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey, err error) {
	curve := ecdh.P256() // curves secp256r1
	privKey, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	pubKey = privKey.PublicKey()

	// fmt.Printf("privKey length: [%v]\n", len(privKey.Bytes()))
	// fmt.Printf("pubKey length: [%v]\n", len(pubKey.Bytes()))

	return
}

func generatePublicKeyFromByte(byteArray []byte) (clientPubKey *ecdh.PublicKey, err error) {
	curve := ecdh.P256()
	clientPubKey, err = curve.NewPublicKey(byteArray)
	if err != nil {
		log.Printf("Error: %v", err)
	}

	return
}

func deriveSharedSecret(myPrivKey *ecdh.PrivateKey, otherPartyPublicKey *ecdh.PublicKey) []byte {

	secretKey, err := myPrivKey.ECDH(otherPartyPublicKey)
	if err != nil {
		log.Printf("Error: %v", err)
	}

	return secretKey
}

func generateKeyId() (encodedSignature string) {
	key := []byte(uuid.New().String())

	// HMAC secret key, The key can be any length, the recommended size is 64 bytes
	message := randomByte(64)

	h := hmac.New(sha256.New, key)
	h.Write(message)
	signature := h.Sum(nil)

	encodedSignature = hex.EncodeToString(signature)
	fmt.Printf("HmacSha256 signature: %s\n", encodedSignature)

	return
}

func aesGcmModeEncrypt(plaintext []byte, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf(err.Error())
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf(err.Error())
		return ""
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)
	fmt.Printf("aesGcmModeEncrypt ====> NonceSize [ %v ]\n", gcm.NonceSize())

	// For AES-GCM, the nonce must be 96-bits (12-bytes) in length
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf(err.Error())
		return ""
	}

	cipherText := gcm.Seal(nonce, nonce, plaintext, nil)

	fmt.Printf("cipherText: %v \n", cipherText)
	fmt.Printf("Ciphertext (Hex): %x\n", cipherText)

	return base64.StdEncoding.EncodeToString(cipherText)
}

func aesGcmModeDecrypt(base64CipherText string, key []byte) string {

	cipherText, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		log.Printf("could not base64 decode: %v", err)
		return ""
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf(err.Error())
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf(err.Error())
		return ""
	}

	fmt.Printf("aesGcmModeDecrypt ====> NonceSize [ %v ]\n", gcm.NonceSize())

	decryptedNonce := cipherText[:gcm.NonceSize()]
	encryptedData := cipherText[gcm.NonceSize():]

	decryptedPlaintext, err := gcm.Open(nil, decryptedNonce, encryptedData, nil)
	if err != nil {
		log.Printf(err.Error())
		return ""
	}

	fmt.Printf("Decrypted Plaintext: %s\n", decryptedPlaintext)

	return string(decryptedPlaintext)
}

func randomByte(length int) []byte {
	key := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Printf(err.Error())
		return make([]byte, 0)
		// return []byte{}
	}

	return key
}

func initRedisConnection(redisConfig RedisConfig) *redis.Client {

	password, err := base64.StdEncoding.DecodeString(redisConfig.Password)

	if err != nil {
		panic(err)
	}

	return database.GetRedisConnection(
		redisConfig.Username,
		string(password),
		redisConfig.Host,
		redisConfig.Port,
		redisConfig.Database,
	)
}

func initRedisClusterConnection() *redis.ClusterClient {
	return database.GetRedisClusterConnection()
}
