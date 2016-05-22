// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"bytes"
	"testing"

	"github.com/magical/argon2"
	"github.com/wg/arc/binary"
	"github.com/wg/ecies/xchacha20poly1305"
)

func TestPublicKeyFormat(t *testing.T) {
	p, _ := keypair(t)
	b, c := StorePublicKey(t, p)

	if b.buffer[1] != Public {
		t.Fatal("serialized type incorrect")
	}

	CheckKeyFormat(t, (*[56]byte)(p), b, c)
}

func TestPrivateKeyFormat(t *testing.T) {
	_, p := keypair(t)
	b, c := StorePrivateKey(t, p)

	if b.buffer[1] != Private {
		t.Fatal("serialized type incorrect")
	}

	CheckKeyFormat(t, (*[56]byte)(p), b, c)
}

func CheckKeyFormat(t *testing.T, k *[56]byte, b *Buffer, c *KeyContainer) {
	key, err := argon2.Key(c.Password, c.Salt[:], int(c.Iterations), 1, int64(c.Memory), KeySize)
	if err != nil {
		t.Fatal("password key derivation failed", err)
	}

	x := xchacha20poly1305.XChaCha20Poly1305{}
	if err := x.Init(key, c.Nonce[:]); err != nil {
		t.Fatal(err)
	}

	dst := [56]byte{}
	tag := [TagSize]byte{}

	x.Decrypt(dst[:], c.Key[:])
	x.Tag(tag[:0])

	if !bytes.Equal(k[:], dst[:]) {
		t.Fatal("decrypted key incorrect")
	}

	if !bytes.Equal(tag[:], c.Tag[:]) {
		t.Fatal("authentication tag incorrect")
	}

	if binary.LE.Uint32(b.buffer[2:6]) != c.Iterations {
		t.Fatal("serialized iterations incorrect")
	}

	if binary.LE.Uint32(b.buffer[6:10]) != c.Memory {
		t.Fatal("serialized memory incorrect")
	}

	if !bytes.Equal(b.buffer[10:42], c.Salt[:]) {
		t.Fatal("serialized salt incorrect")
	}

	if !bytes.Equal(b.buffer[42:58], tag[:]) {
		t.Fatal("serialized tag incorrect")
	}

	if !bytes.Equal(b.buffer[58:82], c.Nonce[:]) {
		t.Fatal("serialized nonce incorrect")
	}
}

func TestPublicPrivateKeypair(t *testing.T) {
	pub, priv := keypair(t)

	shared0, err := ComputeSharedKey(pub, priv, KeySize)
	if err != nil {
		t.Fatal(err)
	}

	_, puc := StorePublicKey(t, pub)
	_, prc := StorePrivateKey(t, priv)

	priv.Zero()

	if err := puc.ReadPublicKey(pub); err != nil {
		t.Fatal("failed to load public key", err)
	}

	if err := prc.ReadPrivateKey(priv); err != nil {
		t.Fatal("failed to load private key", err)
	}

	shared1, err := ComputeSharedKey(pub, priv, KeySize)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(shared0, shared1) {
		t.Fatal("serialized keys incorrect")
	}
}

func TestWrongKeyType(t *testing.T) {
	pub, priv := keypair(t)

	_, pubc := StorePublicKey(t, pub)
	_, privc := StorePrivateKey(t, priv)

	if err := pubc.ReadPrivateKey(priv); err != ErrInvalidPrivateKey {
		t.Fatal("loaded public key as private key")
	}

	if err := privc.ReadPublicKey(pub); err != ErrInvalidPublicKey {
		t.Fatal("loaded private key as public key")
	}
}

func StorePublicKey(t *testing.T, key *PublicKey) (*Buffer, *KeyContainer) {
	b := &Buffer{}
	c := NewKeyContainer(b, []byte(""), 1, 8)

	if err := c.WritePublicKey(key); err != nil {
		t.Fatal("failed to store public key", err)
	}

	b.Rewind()

	return b, c
}

func StorePrivateKey(t *testing.T, key *PrivateKey) (*Buffer, *KeyContainer) {
	b := &Buffer{}
	c := NewKeyContainer(b, []byte("secret"), 1, 8)

	if err := c.WritePrivateKey(key); err != nil {
		t.Fatal("failed to store private key", err)
	}

	b.Rewind()

	return b, c
}
