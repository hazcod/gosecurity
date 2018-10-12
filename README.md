# go-hash [![Go Report Card](https://goreportcard.com/badge/github.com/hazcod/go-hash)](https://goreportcard.com/report/hazcod/go-hash) [![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/HazCod/g-hash/blob/master/LICENSE)
Formats your password hashes in a standard (multihash-like) format so it keeps on working whenever you change algo.
Defaults to Argon2id.

```
func GetHash(input string) (string, error)
func VerifyHash(hash string, input string) (bool, error)
func NeedsRehash(hash string) (bool, error)
```

## Format
An example hash output would look like this:
```
$argon2$i:4:65536$IO+amcBFUXUETmI=$GpiSk2q1+y2DyfRVsg13BmIGE/oM0GLcM0SOs0s/H/s=

$<algo>$<parameters>$salt$key$
```

Where parameters contains information for the specific hashing algorhitm, such as size/modus/memory.
