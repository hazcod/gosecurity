package go_hash

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	bytes1 := GenerateRandomBytes(10)

	if len(bytes1) != 10 {
		t.Errorf("byte length was %d", len(bytes1))
	}

	bytes2 := GenerateRandomBytes(10)
	if bytes.Compare(bytes1, bytes2) == 0 {
		t.Errorf("bytes are not random")
	}
}

func TestHmacKey(t *testing.T) {
	key := GenerateRandomBytes(10)
	input := "test message"

	hmac1, err := hmacKey(input, key)
	if hmac1 == nil || err != nil {
		t.Errorf("Hmac is nil or error occured: %s", err.Error())
	}

	hmac2, err := hmacKey(input, key)
	if hmac2 == nil || err != nil {
		t.Errorf("Hmac2 is nil or error occured: %s", err.Error())
	}

	if bytes.Compare(hmac1, hmac2) != 0 {
		t.Errorf("hmacs are not reproducible")
	}

	hmac3, err := hmacKey(input, GenerateRandomBytes(10))
	if bytes.Compare(hmac1, hmac3) == 0 || err != nil {
		t.Errorf("hmacs look alike or error occured: %s", err.Error())
	}
}

func TestGetHash(t *testing.T) {
	str1 := "This is some text message"
	str2 := "This is another text message"

	hash1, err := GetHash([]byte(str1))
	if err != nil {
		t.Error(err.Error())
	}

	hash2, err := GetHash([]byte(str2))
	if err != nil {
		t.Error(err.Error())
	}

	if hash1 == hash2 {
		t.Error("Hashes are not unique")
	}

	if hash3, _ := GetHash([]byte(str1)); hash3 == hash1 {
		t.Errorf("Salts are not unique: %s", hash3)
	}

	if ! strings.Contains(hash1, DefaultAlgo) {
		t.Errorf("Hash is not using default algo: %s", hash1)
	}

	if ! strings.Contains(hash1, Separator) {
		t.Error("Hash does not use value separator")
	}
}

func TestParseHash(t *testing.T) {
	hash := "$argon2$i:4:65536$IO+amcBFUXUETmI=$GpiSk2q1+y2DyfRVsg13BmIGE/oM0GLcM0SOs0s/H/s="

	hashImpl, paramStr, salt, hashSize, key, err := parseHash(hash)
	if err != nil {
		t.Error(err.Error())
	}

	if hashImpl.GetID() != "argon2" {
		t.Error("algo")
	}

	if paramStr != "i:4:65536" {
		t.Error("params")
	}

	if hashImpl.GetMode() != "i" {
		t.Error("mode")
	}

	if salt == nil {
		t.Error("salt is nil")
	}

	if hashSize != 32 {
		t.Error("incorrect hash size")
	}

	if key != "GpiSk2q1+y2DyfRVsg13BmIGE/oM0GLcM0SOs0s/H/s=" {
		t.Error("key incorrect")
	}
}

func TestVerifyHash(t *testing.T) {
	str1 := "This is some random string +-"
	str2 := "This is another string"

	hash1, _ := GetHash([]byte(str1))
	hash2, _ := GetHash([]byte(str2))

	if valid, err := VerifyHash(hash1, []byte(str1)); valid == false || err != nil {
		t.Error("verify hash is incorrect (hash1!=str1)")
	}

	if valid, err := VerifyHash(hash1, []byte(str2)); valid == true || err != nil {
		t.Error("verify hash is incorrect (hash1=str2)")
	}

	if valid, err := VerifyHash(hash2, []byte(str1)); valid == true || err != nil {
		t.Error("verify hash is incorrect (hash2=str1)")
	}

	if valid, err := VerifyHash(hash2, []byte(str2)); valid == false || err != nil {
		t.Error("verify hash is incorrect (hash2!=str2)")
	}
}

func TestNeedsRehash(t *testing.T) {
	hash1, _ := GetHash([]byte("Some string"))
	if rehash, err := NeedsRehash(hash1); rehash == true || err != nil {
		t.Errorf("incorrect needsrehash (false), %s", err)
	}

	hash2 := "$argon2$i:4:65536$IO+amcBFUXUETmI=$GpiSk2q1+y2DyfRVsg13BmIGE/oM0GLcM0SOs0s/H/s="
	if rehash, err := NeedsRehash(hash2); rehash == false || err != nil {
		t.Errorf("incorrect needsrehash (true), %s", err)
	}
}