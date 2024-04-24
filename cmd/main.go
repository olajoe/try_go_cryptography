package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"try_go_cryptography/internal/aes"

	"github.com/caarlos0/env"
)

type Config struct {
	AESSecretKey string `env:"AES_SECRET_KEY" envDefault:"mock"`
}

func main() {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("cannot parse env")
	}

	// RunAES(&cfg)
	runRSA()
}

func runRSA() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("generate key is error", err)
	}
	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	err = os.WriteFile("private.pem", privateKeyPEM, 0644)
	if err != nil {
		slog.Error("write file private key is error", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("marshal public key is error", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile("public.pem", publicKeyPEM, 0644)
	if err != nil {
		slog.Error("write file public key is error", err)
	}

}

func RunAES(cfg *Config) {
	ciphertext1, err := aes.Encrypt("This is some sensitive information", []byte(cfg.AESSecretKey))
	if err != nil {
		slog.Error("ciphertext1 error", err)
	}
	fmt.Printf("Encrypted ciphertext 1: %s \n", ciphertext1)

	plaintext1, err := aes.Decrypt(ciphertext1, []byte(cfg.AESSecretKey))
	if err != nil {
		slog.Error("plaintext1 error", err)
	}
	fmt.Printf("Decrypted plaintext 1: %s \n", plaintext1)

	ciphertext2, err := aes.Encrypt("Hello", []byte(cfg.AESSecretKey))
	if err != nil {
		slog.Error("ciphertext2 error", err)
	}
	fmt.Printf("Encrypted ciphertext 2: %s \n", ciphertext2)

	plaintext2, err := aes.Decrypt(ciphertext2, []byte(cfg.AESSecretKey))
	if err != nil {
		slog.Error("plaintext2 error", err)
	}
	fmt.Printf("Decrypted plaintext 2: %s \n", plaintext2)
}
