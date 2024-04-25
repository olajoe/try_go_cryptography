package main

import (
	"fmt"
	"log/slog"
	"try_go_cryptography/internal/aes"
	"try_go_cryptography/internal/rsa"

	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
)

type Config struct {
	AESSecretKey string `env:"AES_SECRET_KEY" envDefault:"mock"`
}

func main() {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("cannot parse env")
	}

	if err := godotenv.Load(".env"); err != nil {
		slog.Error("Cannot load ENV from .env file")
	}

	// RunAES(&cfg)
	runRSA()
}

func runRSA() {
	privateKey, publicKey, err := rsa.GenerateKeyPairs(2048)
	if err != nil {
		slog.Error("error genrate key pairs", err)
	}

	sampleText := "Super secure data eiei"
	cipherText, err := rsa.EncryptWithPublickey([]byte(sampleText), publicKey)
	if err != nil {
		slog.Error("encrypt error", err)
	}

	plainText, err := rsa.DecryptWithPrivateKey(cipherText, privateKey)
	if err != nil {
		slog.Error("decrypt error", err)
	}

	if string(plainText) == sampleText {
		fmt.Println("matched")
	} else {
		fmt.Println("unmatched")
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
