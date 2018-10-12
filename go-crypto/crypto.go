package go_crypto

import (
	"crypto/go-hash"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize = 32
	nonceSize = 24
)

func GenerateKey() ([]byte, error) {
	bytes := gohash.GenerateRandomBytes(keySize)

	if len(bytes) != keySize {
		return nil, errors.New("Could not generate enough random bytes for key")
	}

	return bytes, nil
}

func generateNonce() ([]byte, error) {
	bytes := gohash.GenerateRandomBytes(nonceSize)

	if len(bytes) != nonceSize {
		return nil, errors.New("Could not generate enough random bytes for nonce")
	}

	return bytes, nil
}

func Encrypt(input []byte, key []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	if len(nonce) != nonceSize || len(key) != keySize {
		return nil, errors.New("Incorrect key or nonce size")
	}

	var nonceBytes [nonceSize]byte
	copy(nonceBytes[:], nonce)

	var keyBytes [keySize]byte
	copy(keyBytes[:], key)

	return secretbox.Seal(nonce[:], input, &nonceBytes, &keyBytes), nil
}

func Decrypt(input []byte, key []byte) ([]byte, error) {
	var decryptNonce [nonceSize]byte
	copy(decryptNonce[:], input[:nonceSize])

	var keyBytes [keySize]byte
	copy(keyBytes[:], key)

	cipherText := input[nonceSize:]

	decrypted, ok := secretbox.Open(nil, cipherText, &decryptNonce, &keyBytes)
	if !ok {
		return nil, errors.New("Decryption failed")
	}

	return decrypted, nil
}
