package go_hash

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	hashID                   = "argon2"
	argonNumParameters       = 3
	argonDefaultMemoryPasses = 4
	argonDefaultMemorySize   = 64 * 1024
	argonDefaultHashSize     = 32
	argonDefaultMode         = "id"
)

var (
	argonThreads = uint8(runtime.NumCPU() / 2) // max threads = num of cores
	argonModi    = []string{"i", "id"}         // argon modus

	errBadParameters = errors.New("malformed go-hash parameters")
	errUnkownHashMod = errors.New("unkown go-hash modus")
	errBadHashSize   = errors.New("bad go-hash size")
)

type Argon2 struct {
	MemoryPasses uint32 // time setting
	MemorySize   uint32 // memory setting in KiB, e.g. 64*1024 -> 64MB
	Mode         string // modus for argon, i or id
	HashSize     uint32 // go-hash size in bytes (min. 16)
}

func init() {
	Implementations[hashID] = &Argon2{
		MemoryPasses: argonDefaultMemoryPasses,
		MemorySize:   argonDefaultMemorySize,
		Mode:         argonDefaultMode,
		HashSize:     argonDefaultHashSize,
	}
}

func (uc *Argon2) encodedString() string {
	return fmt.Sprintf("%s:%d:%d", uc.Mode, uc.MemoryPasses, uc.MemorySize)
}

func (uc *Argon2) Hash(password, salt []byte) (string, []byte, error) {
	var h []byte
	var err error

	switch uc.Mode {
	case "i":
		h = argon2.Key(password, salt, uc.MemoryPasses, uc.MemorySize, argonThreads, uc.HashSize)
	case "id":
		h = argon2.IDKey(password, salt, uc.MemoryPasses, uc.MemorySize, argonThreads, uc.HashSize)
	default:
		err = errUnkownHashMod
	}

	if err != nil {
		return "", nil, err
	}

	return uc.encodedString(), h, nil
}

func inStrArray(val string, array []string) bool {
	for _, item := range array {
		if item == val {
			return true
		}
	}
	return false
}

func (uc *Argon2) Configure(parameters string, separator string, hashSize uint32) (Hash, error) {
	pars := strings.Split(parameters, separator)

	if len(pars) < argonNumParameters {
		return nil, errBadParameters
	}

	mode := pars[0]

	passes, err := strconv.ParseInt(pars[1], 10, 8)
	if err != nil {
		return nil, errBadParameters
	}

	memory, err := strconv.ParseInt(pars[2], 10, 32)
	if err != nil {
		return nil, errBadParameters
	}

	return uc.configureArgon(mode, uint32(hashSize), uint32(passes), uint32(memory))
}

func (uc *Argon2) configureArgon(mode string, hashSize uint32, passes uint32, memory uint32) (Hash, error) {
	nc := *uc

	if ! inStrArray(mode, argonModi) || hashSize <= 0 || passes <= 0 || memory <= 0 {
		return nil, errBadParameters
	}

	nc.Mode = mode
	nc.HashSize = hashSize
	nc.MemoryPasses = passes
	nc.MemorySize = memory

	return &nc, nil
}

func (uc *Argon2) SetHashSize(size uint32) error {
	if size <= 0 {
		return errBadHashSize
	}

	uc.HashSize = size

	return nil
}

func (uc *Argon2) String() string {
	return fmt.Sprintf("algo:%s mode:%s passes:%d memory:%d", hashID, uc.Mode, uc.MemoryPasses, uc.MemorySize)
}

func (uc *Argon2) GetID() string {
	return hashID
}

func (uc *Argon2) GetMode() string {
	return uc.Mode
}

func (uc *Argon2) GetDefaultHashSize() uint32 {
	return argonDefaultHashSize
}
