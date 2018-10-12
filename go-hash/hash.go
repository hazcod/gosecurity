package gohash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	defaultAlgo  = "argon2"
	minHashParts = 5
	saltSize     = 10

	separator          = "$"
	parameterSeparator = ":"
)

var (
	implementations = make(map[string]hash)

	errUnknownHashImpl = errors.New("unknown go-hash implementation")
	errBadHashFormat   = errors.New("invalid go-hash format")
)

type hash interface {
	Hash(password string, salt []byte) (encodedParams string, key []byte, err error)
	Configure(parameters string, separator string, hashSize uint32) (hash, error)
	GetID() string
	GetMode() string
	GetDefaultHashSize() uint32
	String() string
}

/*
GenerateRandomBytes Generate n number of random bytes
*/
func GenerateRandomBytes(length int) []byte {
	b := make([]byte, length)

	n, err := rand.Read(b)

	if err != nil || n != length {
		return nil
	}

	return b
}

func hmacKey(input string, key []byte) ([]byte, error) {
	hm := hmac.New(sha256.New, []byte(input))
	if _, err := hm.Write(key); err != nil {
		return nil, err
	}
	sum := hm.Sum(nil)

	return sum, nil
}

/*
GetHash Generate a hash based on the input and return it hexadecimal
*/
func GetHash(input string) (string, error) {

	var hashImpl = defaultAlgo
	var hasher = implementations[hashImpl]

	var salt = GenerateRandomBytes(saltSize)

	params, hash, err := hasher.Hash(input, salt[:])
	if err != nil {
		return "", err
	}

	hashSize := byte(len(hash))
	salt = append([]byte{hashSize}, salt...)

	encodedSalt := base64.StdEncoding.EncodeToString(salt)

	prefix := fmt.Sprintf("$%v$%v$%v$", hashImpl, params, encodedSalt)
	hmacHash, err := hmacKey(prefix, hash)
	if err != nil {
		return "", err
	}

	encodedHash := base64.StdEncoding.EncodeToString(hmacHash)

	return prefix + encodedHash, nil
}

func parseHash(hash string) (hash, string, []byte, uint32, string, error) {
	parts := strings.Split(hash, separator)

	if len(parts) < minHashParts {
		return nil, "", nil, 0, "", errBadHashFormat
	}

	hashImpl, found := implementations[parts[1]]
	if !found {
		return nil, "", nil, 0, "", errUnknownHashImpl
	}

	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, "", nil, 0, "", errBadHashFormat
	}

	hashSize := uint32(salt[0])
	params := parts[2]
	salt = salt[1:]
	key := parts[4]

	hashImpl, err = hashImpl.Configure(params, parameterSeparator, hashImpl.GetDefaultHashSize())
	if err != nil {
		return nil, "", nil, 0, "", err
	}

	return hashImpl, params, salt, hashSize, key, nil
}

/*
VerifyHash Check whether the given value matches the given hash
*/
func VerifyHash(hash string, input string) (bool, error) {
	hashImpl, paramStr, salt, hashSize, key, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	hashImpl, err = hashImpl.Configure(paramStr, parameterSeparator, uint32(hashSize))
	if err != nil {
		return false, err
	}

	_, otherKey, err := hashImpl.Hash(input, salt)
	if err != nil {
		return false, err
	}

	hashed, err := hmacKey(hash[:len(hash)-len(key)], otherKey)
	if err != nil {
		return false, err
	}

	baseMac, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false, err
	}

	return hmac.Equal(baseMac, hashed), nil
}

/*
NeedsRehash Check whether the given hash needs a newer algorithm, parameters or bigger size
*/
func NeedsRehash(hash string) (bool, error) {

	hashImpl, _, salt, hashSize, _, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	var defaultImpl = implementations[defaultAlgo]

	return hashImpl.GetID() != defaultImpl.GetID() || hashImpl.GetMode() != defaultImpl.GetMode() || len(salt) < saltSize || hashSize < hashImpl.GetDefaultHashSize(), nil
}
