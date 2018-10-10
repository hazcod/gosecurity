package hash

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	hashArgonID = "argon2"

	argonNumParameters   	= 3
	argonDefaultMemoryPasses= 4
	argonDefaultMemorySize  = 64 * 1024
	argonDefaultHashSize 	= 32
	argonDefaultMode     	= "id"
)

var (
	argonThreads = uint8(runtime.NumCPU() / 2) // max threads = num of cores
	argonModi = []string{ "i", "id" } 		   // argon modus

	errBadParameters	= errors.New("malformed hash parameters")
	errUnkownHashMod    = errors.New("unkown hash modus")
	errBadHashSize		= errors.New("bad hash size")
)


type HashArgon struct {
	MemoryPasses uint32 // time setting
	MemorySize   uint32 // memory setting in KiB, e.g. 64*1024 -> 64MB
	Mode     	 string // modus for argon, i or id
	HashSize 	 uint32 // hash size in bytes (min. 16)
}

func init() {
	HashImplementations[hashArgonID] = &HashArgon{
		MemoryPasses: argonDefaultMemoryPasses,
		MemorySize: argonDefaultMemorySize,
		Mode: argonDefaultMode,
		HashSize: argonDefaultHashSize,
	}
}

func (uc *HashArgon) encodedString() string {
	return fmt.Sprintf("%s:%d:%d", uc.Mode, uc.MemoryPasses, uc.MemorySize)
}

func (uc *HashArgon) Hash(password, salt []byte) (string, []byte, error) {
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

func inStrArray(val string, array []string) (ok bool) {
	var i int
	for i = range array {
		if ok = array[i] == val; ok {
			return true
		}
	}
	return false
}

func (uc *HashArgon) Configure(parameters string, separator string, hashSize uint32) (HashImplementation, error) {
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

func (uc *HashArgon) configureArgon(mode string, hashSize uint32, passes uint32, memory uint32) (HashImplementation, error) {
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

func (uc *HashArgon) GetDefaultLength() (int) {
	return argonDefaultHashSize
}

func (uc *HashArgon) GetNumParameters() (int) {
	return argonNumParameters
}

func (uc *HashArgon) SetHashSize(size uint32) (error) {
	if size <= 0 {
		return errBadHashSize
	}

	uc.HashSize = size

	return nil
}

func (uc *HashArgon) GetDefaultHashSize() int {
	return argonDefaultHashSize
}

func (uc *HashArgon) GetID() string {
	return hashArgonID
}

func (uc *HashArgon) String() string {
	return fmt.Sprintf("algo:%s mode:%s passes:%d memory:%d", hashArgonID, uc.Mode, uc.MemoryPasses, uc.MemorySize)
}
