# go-hash
Formats your password hashes in a standard (multihash-like) format so it keeps on working whenever you change algo.
Defaults to Argon2id.

```
func GetHash(input []byte) (string, error)
func VerifyHash(hash string, input []byte) (bool, error)
func NeedsRehash(hash string) (bool, error)
```
