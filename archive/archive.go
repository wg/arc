// Copyright (C) 2016 - Will Glozer. All rights reserved.

package archive

import (
	"crypto/rand"
	"crypto/subtle"
	"io"

	"github.com/wg/ecies/xchacha20poly1305"
)

const KeySize = xchacha20poly1305.KeySize

type Archive struct {
	xchacha20poly1305.XChaCha20Poly1305
	tag [xchacha20poly1305.TagSize]byte
	io.Reader
	io.Writer
}

func NewArchiveFromReader(r io.Reader, key []byte) (*Archive, error) {
	var nonce [xchacha20poly1305.NonceSize]byte
	a := &Archive{Reader: r}

	if _, err := io.ReadFull(r, a.tag[:]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, err
	}

	err := a.Init(key, nonce[:])
	return a, err
}

func NewArchiveForWriter(w io.Writer, key []byte) (*Archive, error) {
	var nonce [xchacha20poly1305.NonceSize]byte
	a := &Archive{Writer: w}

	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	if err := a.Init(key, nonce[:]); err != nil {
		return nil, err
	}

	if _, err := w.Write(a.tag[:]); err != nil {
		return nil, err
	}

	if _, err := w.Write(nonce[:]); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Archive) Read(b []byte) (int, error) {
	n, err := a.Reader.Read(b)
	a.Decrypt(b[:n], b[:n])
	return n, err
}

func (a *Archive) Write(b []byte) (int, error) {
	a.Encrypt(b, b)
	return a.Writer.Write(b)
}

func (a *Archive) Verify() bool {
	var tag [xchacha20poly1305.TagSize]byte
	a.Tag(tag[:0])
	return subtle.ConstantTimeCompare(a.tag[:], tag[:]) == 1
}
