// Copyright (C) 2016 - Will Glozer. All rights reserved.

package ecies

import (
	"crypto/subtle"
	"errors"

	"github.com/dchest/blake2b"
	"github.com/wg/ecies/xchacha20poly1305"
)

var (
	ErrBoxAuthFailed = errors.New("box: message auth failed")
	ErrBoxTooSmall   = errors.New("box: destination too small")
	ErrBoxInvariant  = errors.New("box: invariant violation")
)

type Box struct {
	key [xchacha20poly1305.KeySize]byte
	xchacha20poly1305.XChaCha20Poly1305
}

func NewX25519XChaCha20Poly1305(publicKey, privateKey *[32]byte) (*Box, error) {
	var secret [32]byte
	if err := X25519(&secret, publicKey, privateKey); err != nil {
		return nil, err
	}
	return newXChaCha20Poly1305Box(secret[:])
}

func NewX448XChaCha20Poly1305(publicKey, privateKey *[56]byte) (*Box, error) {
	var secret [56]byte
	if err := X448(&secret, publicKey, privateKey); err != nil {
		return nil, err
	}
	return newXChaCha20Poly1305Box(secret[:])
}

func (b *Box) Seal(dst, msg, nonce []byte) error {
	if cap(dst) < len(msg)+xchacha20poly1305.TagSize {
		return ErrBoxTooSmall
	}

	if err := b.Init(b.key[:], nonce); err != nil {
		return err
	}

	n := len(msg)
	b.Encrypt(dst, msg)
	b.Tag(dst[n:n])

	return nil
}

func (b *Box) Open(dst, msg, nonce []byte) error {
	if cap(dst) < len(msg)-xchacha20poly1305.TagSize {
		return ErrBoxTooSmall
	}

	if err := b.Init(b.key[:], nonce); err != nil {
		return err
	}

	n := len(msg) - xchacha20poly1305.TagSize
	msg, tag := msg[:n], msg[n:]
	b.Decrypt(dst, msg)

	if subtle.ConstantTimeCompare(tag, b.Tag(nil)) != 1 {
		return ErrBoxAuthFailed
	}

	return nil
}

func newXChaCha20Poly1305Box(secret []byte) (*Box, error) {
	h, err := blake2b.New(&blake2b.Config{
		Size: xchacha20poly1305.KeySize,
	})

	if err != nil {
		return nil, ErrBoxInvariant
	}

	box := &Box{}
	h.Write(secret)
	h.Sum(box.key[:0])

	return box, nil
}
