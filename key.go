// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/dchest/blake2b"
	"github.com/magical/argon2"
	"github.com/wg/arc/binary"
	"github.com/wg/ecies"
	"github.com/wg/ecies/xchacha20poly1305"
)

const (
	Public  = 0x01
	Private = 0x02
	NonSize = xchacha20poly1305.NonceSize
	TagSize = xchacha20poly1305.TagSize
)

type (
	PublicKey  [56]byte
	PrivateKey [56]byte
)

type KeyContainer struct {
	Version    byte
	Type       byte
	Iterations uint32
	Memory     uint32
	Salt       [32]byte
	Tag        [TagSize]byte
	Nonce      [NonSize]byte
	Key        [56]byte
	Password   []byte
	File       io.ReadWriteCloser
}

var (
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidPrivateKey = errors.New("invalid private key")
)

func GenerateKeypair() (*PublicKey, *PrivateKey, error) {
	var public, private [56]byte
	err := ecies.GenerateCurve448Key(rand.Reader, &public, &private)
	return (*PublicKey)(&public), (*PrivateKey)(&private), err
}

func ComputeSharedKey(public *PublicKey, private *PrivateKey, size uint8) ([]byte, error) {
	hash, err := blake2b.New(&blake2b.Config{Size: size})
	if err != nil {
		return nil, err
	}

	var secret [56]byte
	err = ecies.X448(&secret, (*[56]byte)(public), (*[56]byte)(private))
	hash.Write(secret[:])

	for i := range secret {
		secret[i] = 0
	}

	return hash.Sum(nil), err
}

func (private *PrivateKey) Zero() {
	for i := range private {
		private[i] = 0
	}
}

func NewKeyContainer(file io.ReadWriteCloser, password []byte, iterations, memory uint32) *KeyContainer {
	return &KeyContainer{
		Version:    1,
		Iterations: iterations,
		Memory:     memory,
		Password:   password,
		File:       file,
	}
}

func (c *KeyContainer) ReadPublicKey(key *PublicKey) error {
	return c.read(Public, (*[56]byte)(key))
}

func (c *KeyContainer) WritePublicKey(key *PublicKey) error {
	return c.write(Public, (*[56]byte)(key))
}

func (c *KeyContainer) ReadPrivateKey(key *PrivateKey) error {
	return c.read(Private, (*[56]byte)(key))
}

func (c *KeyContainer) WritePrivateKey(key *PrivateKey) error {
	return c.write(Private, (*[56]byte)(key))
}

func (c *KeyContainer) Close() error {
	return c.File.Close()
}

func (c *KeyContainer) read(t byte, key *[56]byte) error {
	switch err := binary.Read(c.File, binary.LE, c); {
	case err != nil:
		return err
	case c.Type != t && t == Public:
		return ErrInvalidPublicKey
	case c.Type != t && t == Private:
		return ErrInvalidPrivateKey
	}

	var tag [TagSize]byte
	x, err := c.cipher()
	if err != nil {
		return err
	}

	x.Decrypt(key[:], c.Key[:])
	x.Tag(tag[:0])

	if subtle.ConstantTimeCompare(c.Tag[:], tag[:]) != 1 {
		return ErrInvalidPrivateKey
	}

	return nil
}

func (c *KeyContainer) write(t byte, key *[56]byte) error {
	c.Type = t

	if _, err := rand.Read(c.Salt[:]); err != nil {
		return err
	}

	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return err
	}

	x, err := c.cipher()
	if err != nil {
		return err
	}

	x.Encrypt(c.Key[:], key[:])
	x.Tag(c.Tag[:0])

	return binary.Write(c.File, binary.LE, c)
}

func (c *KeyContainer) cipher() (*xchacha20poly1305.XChaCha20Poly1305, error) {
	var (
		salt       = c.Salt[:]
		iterations = int(c.Iterations)
		memory     = int64(c.Memory)
		keySize    = xchacha20poly1305.KeySize
	)

	key, err := argon2.Key(c.Password, salt, iterations, 1, memory, keySize)
	if err != nil {
		return nil, err
	}

	x := &xchacha20poly1305.XChaCha20Poly1305{}
	return x, x.Init(key[:], c.Nonce[:])
}
