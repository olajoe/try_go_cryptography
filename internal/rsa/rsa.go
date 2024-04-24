package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func GenerateKeyPairs(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

func ExportPrivateKeyAsPEMString(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

func ExportPublicKeyAsPEMString(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

func ImportPEMStringToPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM string data")
	}

	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

func ImportPEMStringToPublicKey(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM string data")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not RSA public key")
	}

	return pubKey, nil
}

func EncryptWithPublickey(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, msg)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func DecryptWithPrivateKey(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
