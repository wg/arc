// Copyright (C) 2016 - Will Glozer. All rights reserved.

// Package xchacha20poly1305 implements an AEAD construction
// similar to NaCl's xsalsa20poly1305 secretbox, but using
// XChaCha20 instead of XSalsa20.
package xchacha20poly1305

import (
	"schwanenlied.me/yawning/chacha20"
	"schwanenlied.me/yawning/poly1305"
)

const (
	KeySize   = chacha20.KeySize
	NonceSize = chacha20.XNonceSize
	TagSize   = poly1305.Size
)

type XChaCha20Poly1305 struct {
	chacha20.Cipher
	poly1305.Poly1305
}

func New(key *[KeySize]byte, nonce *[NonceSize]byte) *XChaCha20Poly1305 {
	x := &XChaCha20Poly1305{}
	x.Init(key[:], nonce[:])
	return x
}

func (x *XChaCha20Poly1305) Init(key, nonce []byte) error {
	err := x.ReKey(key, nonce)
	if err == nil {
		x.initPoly1305()
		x.Seek(1)
	}
	return err
}

func (x *XChaCha20Poly1305) Auth(src []byte) {
	if len(src) > 0 {
		x.Poly1305.Write(src)
	}
}

func (x *XChaCha20Poly1305) Decrypt(dst, src []byte) {
	x.Poly1305.Write(src)
	x.XORKeyStream(dst, src)
}

func (x *XChaCha20Poly1305) Encrypt(dst, src []byte) {
	n := len(src)
	x.XORKeyStream(dst, src)
	x.Poly1305.Write(dst[:n])
}

func (x *XChaCha20Poly1305) Tag(b []byte) []byte {
	return x.Poly1305.Sum(b)
}

func (x *XChaCha20Poly1305) Reset() {
	x.Cipher.Reset()
}

func (x *XChaCha20Poly1305) TagSize() int {
	return TagSize
}

func (x *XChaCha20Poly1305) initPoly1305() {
	var key [poly1305.KeySize]byte
	x.KeyStream(key[:])
	x.Poly1305.Init(key[:])
	for i := range key {
		key[i] = 0
	}
}
