package gocrypto

import (
	"encoding/hex"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	if _, err := GenerateKey(); err != nil {
		t.Error(err.Error())
	}
}

func TestEncrypt(t *testing.T) {
	key, _ := GenerateKey()
	message := "This is a secret message"

	cipherText, err := Encrypt([]byte(message), key)
	if err != nil {
		t.Error(err)
	}

	if len(cipherText) == 0 {
		t.Errorf("Empty ciphertext")
	}
}

func TestEncrypt2(t *testing.T) {
	str := "This is a secret message"
	cipherText := "61f67e49187a99f5bf98c30b605b39bee0ba605d46b9e194e1fadc0c0247b1e36877fef008d80718a962850cad9b22793e19c2fd2ba0f27531e4004628ea29ab"
	key := "622082e1a6bc9bc76a4064178db4e6790e34e8ed2a89550abe87fcfb22c9360e"

	cipherBytes, _ := hex.DecodeString(cipherText)
	keyBytes, _ := hex.DecodeString(key)

	decoded, err := Decrypt(cipherBytes, keyBytes)
	if err != nil {
		t.Error(err)
	}

	if string(decoded) != str {
		t.Errorf("Decoded string does not match: %s", string(decoded))
	}

	if _, err = Decrypt(cipherBytes, keyBytes[10:]); err == nil {
		t.Error("Can decode with invalid key")
	}
}
