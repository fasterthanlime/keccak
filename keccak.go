package keccak

// #include "KeccakNISTInterface.h"
import "C"
import (
    "hash"
    "errors"
    "unsafe"
)

type keccak struct {
    hashState C.hashState
    bitlen C.int
    DataLength C.DataLength
}

func newKeccak(bitlen int) hash.Hash {
    var k keccak
    k.bitlen = C.int(bitlen)
    if C.Init(&k.hashState, k.bitlen) == C.BAD_HASHLEN {
        panic("bad hashlen")
    }
    return &k
}

func New224() hash.Hash {
    return newKeccak(224)
}

func New256() hash.Hash {
    return newKeccak(256)
}

func New384() hash.Hash {
    return newKeccak(384)
}

func New512() hash.Hash {
    return newKeccak(512)
}

func (k *keccak) Write(b []byte) (int, error) {
    n := len(b)
    dl := C.DataLength(n * 8)
    if n == 0 {
        return 0, nil
    }
    p := (*C.BitSequence)(unsafe.Pointer(&b[0]))
    if C.Update(&k.hashState, p, dl) != C.SUCCESS {
        return 0, errors.New("keccak write error")
    }
    return n, nil
}

func (k *keccak) BlockSize() int {
    switch int(k.bitlen) {
    case 224: return 1152/8
    case 256: return 1088/8
    case 384: return  832/8
    case 512: return  576/8
    default:  return    1
    }
}

func (k *keccak) Reset() {
    if C.Init(&k.hashState, k.bitlen) != C.BAD_HASHLEN {
        panic("bad hashlen")
    }
}

func (k *keccak) Size() int {
    return int(k.bitlen) / 8
}

func (k *keccak) Sum(b []byte) []byte {
    k0 := *k

    buf := make([]byte, k.Size(), k.Size())

    if C.Final(&k0.hashState, (*C.BitSequence)(unsafe.Pointer(&buf[0]))) != C.SUCCESS {
        panic("keccak sum error")
    }

    return append(b, buf...)
}
