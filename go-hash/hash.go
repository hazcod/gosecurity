package go_hash

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
	DefaultAlgo  = "argon2"
	MinHashParts = 5
	SaltSize     = 10

	Separator          = "$"
	ParameterSeparator = ":"
)

var (
	Implementations = make(map[string]Hash)

	errUnknownHashImpl = errors.New("unknown go-hash implementation")
	errBadHashFormat   = errors.New("invalid go-hash format")
)

type Hash interface {
	Hash(password, salt []byte) (encodedParams string, key []byte, err error)
	Configure(string, string, uint32) (Hash, error)
	GetID() string
	GetMode() string
	GetDefaultHashSize() uint32
	String() string
}

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

func GetHash(input []byte) (string, error) {

	var hashImpl = DefaultAlgo
	var hasher = Implementations[hashImpl]

	var salt = GenerateRandomBytes(SaltSize)

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

func parseHash(hash string) (Hash, string, []byte, uint32, string, error) {
	parts := strings.Split(hash, Separator)

	if len(parts) < MinHashParts {
		return nil, "", nil, 0, "", errBadHashFormat
	}

	hashImpl, found := Implementations[parts[1]]
	if ! found {
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

	hashImpl, err = hashImpl.Configure(params, ParameterSeparator, hashImpl.GetDefaultHashSize())
	if err != nil {
		return nil, "", nil, 0, "", err
	}

	return hashImpl, params, salt, hashSize, key, nil
}

func VerifyHash(hash string, input []byte) (bool, error) {
	hashImpl, paramStr, salt, hashSize, key, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	hashImpl, err = hashImpl.Configure(paramStr, ParameterSeparator, uint32(hashSize))
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

func NeedsRehash(hash string) (bool, error) {

	hashImpl, _, salt, hashSize, _, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	var defaultImpl = Implementations[DefaultAlgo]

	return hashImpl.GetID() != defaultImpl.GetID() || hashImpl.GetMode() != defaultImpl.GetMode() || len(salt) < SaltSize || hashSize < hashImpl.GetDefaultHashSize(), nil
}
