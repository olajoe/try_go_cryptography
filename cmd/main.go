package main

import (
	"fmt"
	"log/slog"
	"try_go_cryptography/internal/aes"

	"github.com/caarlos0/env"
)

type Config struct {
	AESSecretKey string `env:"AES_SECRET_KEY" envDefault:"mock"`
	RSASecretKey string `env:"RSA_SECRET_KEY" envDefault:"mock"`
}

func main() {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("cannot parse env")
	}

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
