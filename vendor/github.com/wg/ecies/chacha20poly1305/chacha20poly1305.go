// Copyright (C) 2016 - Will Glozer. All rights reserved.

// Package chacha20poly1305 implements the AEAD_CHACHA20_POLY1305
// construction as specified in RFC 7539.
package chacha20poly1305

import (
	"encoding/binary"

	"schwanenlied.me/yawning/chacha20"
	"schwanenlied.me/yawning/poly1305"
)

const (
	KeySize   = chacha20.KeySize
	NonceSize = chacha20.INonceSize
	TagSize   = poly1305.Size
)

var padding [16]byte

type ChaCha20Poly1305 struct {
	a, n uint64
	chacha20.Cipher
	poly1305.Poly1305
}

func New(key *[KeySize]byte, nonce *[NonceSize]byte) *ChaCha20Poly1305 {
	x := &ChaCha20Poly1305{}
	x.Init(key[:], nonce[:])
	return x
}

func (x *ChaCha20Poly1305) Init(key, nonce []byte) error {
	err := x.ReKey(key, nonce)
	if err == nil {
		x.initPoly1305()
		x.Seek(1)
		x.a = 0
		x.n = 0
	}
	return err
}

func (x *ChaCha20Poly1305) Auth(src []byte) {
	if n := len(src); n > 0 {
		x.Poly1305.Write(src)
		x.a = uint64(n)
		x.Poly1305.Write(padding[:16-n%16])
	}
}

func (x *ChaCha20Poly1305) Decrypt(dst, src []byte) {
	x.Poly1305.Write(src)
	x.XORKeyStream(dst, src)
	x.n += uint64(len(src))
}

func (x *ChaCha20Poly1305) Encrypt(dst, src []byte) {
	n := len(src)
	x.XORKeyStream(dst, src)
	x.Poly1305.Write(dst[:n])
	x.n += uint64(n)
}

func (x *ChaCha20Poly1305) Tag(b []byte) []byte {
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[0:], uint64(x.a))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(x.n))
	x.Poly1305.Write(padding[:16-x.n%16])
	x.Poly1305.Write(lengths[:])
	return x.Poly1305.Sum(b)
}

func (x *ChaCha20Poly1305) Reset() {
	x.Cipher.Reset()
}

func (x *ChaCha20Poly1305) TagSize() int {
	return TagSize
}

func (x *ChaCha20Poly1305) initPoly1305() {
	var key [poly1305.KeySize]byte
	x.KeyStream(key[:])
	x.Poly1305.Init(key[:])
	for i := range key {
		key[i] = 0
	}
}
