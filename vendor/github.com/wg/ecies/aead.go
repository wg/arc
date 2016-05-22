// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/wg/ecies/chacha20poly1305"
	"github.com/wg/ecies/xchacha20poly1305"
)

var (
	ErrInvalidKeySize = errors.New("cipher: invalid key length")
	ErrAuthFailed     = errors.New("cipher: message auth failed")
)

type AEAD struct {
	key       []byte
	nonceSize int
	tagSize   int
	Cipher
}

func NewXChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != xchacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	core := &xchacha20poly1305.XChaCha20Poly1305{}

	return &AEAD{
		key:       key,
		nonceSize: xchacha20poly1305.NonceSize,
		tagSize:   xchacha20poly1305.TagSize,
		Cipher:    core,
	}, nil
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	core := &chacha20poly1305.ChaCha20Poly1305{}

	return &AEAD{
		key:       key,
		nonceSize: chacha20poly1305.NonceSize,
		tagSize:   chacha20poly1305.TagSize,
		Cipher:    core,
	}, nil
}

func (a *AEAD) NonceSize() int {
	return a.nonceSize
}

func (a *AEAD) Overhead() int {
	return a.tagSize
}

func (a *AEAD) Open(dst, nonce, src, aad []byte) ([]byte, error) {
	err := a.Init(a.key, nonce)
	if err != nil {
		return nil, err
	}

	n := len(src) - a.tagSize
	dst, ret := extend(dst, n)
	src, tag := src[:n], src[n:]

	a.Auth(aad)
	a.Decrypt(dst, src)

	if subtle.ConstantTimeCompare(tag, a.Tag(nil)) != 1 {
		return nil, ErrAuthFailed
	}

	return ret, nil
}

func (a *AEAD) Seal(dst, nonce, src, aad []byte) []byte {
	err := a.Init(a.key, nonce)
	if err != nil {
		panic(err)
	}

	n := len(src) + a.tagSize
	dst, ret := extend(dst, n)
	tag := dst[len(src):]

	a.Auth(aad)
	a.Encrypt(dst, src)
	a.Tag(tag[:0])

	return ret
}

func extend(dst []byte, n int) ([]byte, []byte) {
	if len(dst) < n {
		dst = append(dst, make([]byte, n)...)
	}
	return dst, dst[:n]
}
