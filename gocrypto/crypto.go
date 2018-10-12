package gocrypto

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"gosecurity/gohash"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	errGenKey   = errors.New("Could not generate enough random bytes for key")
	errGenNonce = errors.New("Could not generate enough random bytes for nonce")
	errKeyNonce = errors.New("Incorrect key or nonce size")
	errDecrypt  = errors.New("Decryption failed")
)

/*
GenerateKey Generates a series of random bytes used as a secret key for encrypting/decrypting
*/
func GenerateKey() ([]byte, error) {
	bytes := gohash.GenerateRandomBytes(keySize)

	if len(bytes) != keySize {
		return nil, errGenKey
	}

	return bytes, nil
}

func generateNonce() ([]byte, error) {
	bytes := gohash.GenerateRandomBytes(nonceSize)

	if len(bytes) != nonceSize {
		return nil, errGenNonce
	}

	return bytes, nil
}

/*
Encrypt Encrypts (authenticated) a series of bytes given the secret key
*/
func Encrypt(input []byte, key []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	if len(nonce) != nonceSize || len(key) != keySize {
		return nil, errKeyNonce
	}

	var nonceBytes [nonceSize]byte
	copy(nonceBytes[:], nonce)

	var keyBytes [keySize]byte
	copy(keyBytes[:], key)

	return secretbox.Seal(nonce[:], input, &nonceBytes, &keyBytes), nil
}

/*
Decrypt Decrypt (authenticated) a series of bytes given the secret key
*/
func Decrypt(input []byte, key []byte) ([]byte, error) {
	var decryptNonce [nonceSize]byte
	copy(decryptNonce[:], input[:nonceSize])

	var keyBytes [keySize]byte
	copy(keyBytes[:], key)

	cipherText := input[nonceSize:]

	decrypted, ok := secretbox.Open(nil, cipherText, &decryptNonce, &keyBytes)
	if !ok {
		return nil, errDecrypt
	}

	return decrypted, nil
}
