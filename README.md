# gosecurity [![Go Report Card](https://goreportcard.com/badge/github.com/hazcod/gosecurity)](https://goreportcard.com/report/hazcod/gosecurity) [![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/HazCod/gosecurity/blob/master/LICENSE)
Wrapper library that contains security-related stuff.

### gocrypto
Encrypt and decrypt stuff using authenticated state-of-the-art crypto, provided by golang.org/x/crypto/nacl/secretbox.

#### usage
```
func GenerateKey() ([]byte, error)
func Encrypt(input []byte, key []byte) ([]byte, error)
func Decrypt(input []byte, key []byte) ([]byte, error)
```

#### format
```
<nonce(24b)><ciphertext>
```

### gohash
Formats your password hashes in a standard (multihash-like) format so it keeps on working whenever you change algo.
Defaults to Argon2id from golang.org/x/crypto/argon2.

#### usage
```
func GetHash(input string) (string, error)
func VerifyHash(hash string, input string) (bool, error)
func NeedsRehash(hash string) (bool, error)
```

#### format
```
$argon2$i:4:65536$IO+amcBFUXUETmI=$GpiSk2q1+y2DyfRVsg13BmIGE/oM0GLcM0SOs0s/H/s=

$<algo>$<parameters>$salt$key$
```

Where parameters contains information for the specific hashing algorhitm, such as size/modus/memory.
