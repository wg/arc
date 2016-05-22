// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"io"

	"github.com/codahale/sss"
	"github.com/magical/argon2"
	"github.com/wg/arc/archive"
	"github.com/wg/arc/binary"
)

const (
	Version  = 0x01
	Password = 0x01
	Curve448 = 0x02
	Shard    = 0x03
	KeySize  = archive.KeySize
)

type Archiver interface {
	Reader() (*Reader, error)
	Writer() (*Writer, error)
}

type Reader struct {
	buffer *bufio.Reader
	files  []File
	*archive.Reader
}

type Writer struct {
	buffer *bufio.Writer
	files  []File
	tagAt  int64
	*archive.Writer
}

var (
	ErrInvalidArchive  = errors.New("archive: verify failed")
	ErrInvalidVersion  = errors.New("archive: unsupported version")
	ErrPasswordArchive = errors.New("archive: password archive")
	ErrCurve448Archive = errors.New("archive: curve448 archive")
	ErrShardArchive    = errors.New("archive: shard archive")
)

// A PasswordArchive is encrypted with a key derived from a password,
// cost parameters, and cryptographically secure random salt using the
// Argon2 password hashing function.
type PasswordArchive struct {
	Version    byte
	Type       byte
	Iterations uint32
	Memory     uint32
	Salt       [32]byte
	Password   []byte
	File       File
}

func NewPasswordArchive(password []byte, iterations, memory uint32, file File) *PasswordArchive {
	return &PasswordArchive{
		Version:    Version,
		Type:       Password,
		Iterations: iterations,
		Memory:     memory,
		Password:   password,
		File:       file,
	}
}

func (a *PasswordArchive) Reader() (*Reader, error) {
	err := binary.Read(a.File, binary.LE, a)
	if err != nil {
		return nil, err
	}

	switch {
	case a.Version != Version:
		return nil, ErrInvalidVersion
	case a.Type == Curve448:
		return nil, ErrCurve448Archive
	case a.Type == Shard:
		return nil, ErrShardArchive
	}

	key, err := a.Key()
	if err != nil {
		return nil, err
	}

	return newArchiveReader(key, a.File, a.File)
}

func (a *PasswordArchive) Writer() (*Writer, error) {
	_, err := rand.Read(a.Salt[:])
	if err != nil {
		return nil, err
	}

	err = binary.Write(a.File, binary.LE, a)
	if err != nil {
		return nil, err
	}

	key, err := a.Key()
	if err != nil {
		return nil, err
	}

	return newArchiveWriter(key, a.File, a.File)
}

func (a *PasswordArchive) Key() ([]byte, error) {
	var (
		password   = a.Password
		salt       = a.Salt[:]
		iterations = int(a.Iterations)
		memory     = int64(a.Memory)
	)
	return argon2.Key(password, salt, iterations, 1, memory, KeySize)
}

// A Curve448Archive is encrypted with a key derived from applying
// BLAKE2b to the shared secret derived from an X448 ECDH key exchange
// with an ephemeral private key and static public key.
type Curve448Archive struct {
	Version    byte
	Type       byte
	Ephemeral  PublicKey
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
	File       File
}

func NewCurve448Archive(public *PublicKey, private *PrivateKey, file File) *Curve448Archive {
	return &Curve448Archive{
		Version:    Version,
		Type:       Curve448,
		PublicKey:  public,
		PrivateKey: private,
		File:       file,
	}
}

func (a *Curve448Archive) Reader() (*Reader, error) {
	err := binary.Read(a.File, binary.LE, a)
	if err != nil {
		return nil, err
	}

	switch {
	case a.Version != Version:
		return nil, ErrInvalidVersion
	case a.Type == Password:
		return nil, ErrPasswordArchive
	case a.Type == Shard:
		return nil, ErrShardArchive
	}

	key, err := ComputeSharedKey(&a.Ephemeral, a.PrivateKey, KeySize)
	if err != nil {
		return nil, err
	}

	return newArchiveReader(key, a.File, a.File)
}

func (a *Curve448Archive) Writer() (*Writer, error) {
	ephemeralPublicKey, ephemeralPrivateKey, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	defer ephemeralPrivateKey.Zero()

	key, err := ComputeSharedKey(a.PublicKey, ephemeralPrivateKey, KeySize)
	if err != nil {
		return nil, err
	}

	a.Ephemeral = *ephemeralPublicKey
	err = binary.Write(a.File, binary.LE, a)
	if err != nil {
		return nil, err
	}

	return newArchiveWriter(key, a.File, a.File)
}

// A ShardArchive is encrypted with a key consisting of cryptographically
// secure random bytes. That key is split into n shards using Shamir's
// Secret Sharing algorithm and one archive is generate for each shard.
// k shards must be present to recreate the key.
type ShardArchive struct {
	Version   byte
	Type      byte
	ID        byte
	Share     [KeySize]byte
	Threshold int
	File      File
	Shards    []*ShardArchive
}

func NewShardArchive(threshold int, files []File) *ShardArchive {
	shards := make([]*ShardArchive, len(files))

	for i, file := range files {
		shards[i] = &ShardArchive{
			Version:   Version,
			Type:      Shard,
			Threshold: threshold,
			File:      file,
			Shards:    shards,
		}
	}

	return shards[0]
}

func (a *ShardArchive) Reader() (*Reader, error) {
	shares := make(map[byte][]byte, len(a.Shards))

	for _, shard := range a.Shards {
		err := binary.Read(shard.File, binary.LE, shard)
		if err != nil {
			return nil, err
		}

		switch {
		case shard.Version != Version:
			return nil, ErrInvalidVersion
		case shard.Type == Password:
			return nil, ErrPasswordArchive
		case shard.Type == Curve448:
			return nil, ErrCurve448Archive
		}

		shares[shard.ID] = shard.Share[:]
	}

	key := sss.Combine(shares)

	return newArchiveReader(key, a.File, a.Files()...)
}

func (a *ShardArchive) Writer() (*Writer, error) {
	var key [32]byte

	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	n := byte(len(a.Shards))
	k := byte(a.Threshold)

	shares, err := sss.Split(n, k, key[:])
	if err != nil {
		return nil, err
	}

	writers := make([]io.Writer, len(a.Shards))
	for id, share := range shares {
		index := id - 1
		shard := a.Shards[index]

		shard.ID = id
		copy(shard.Share[:], share)

		err = binary.Write(shard.File, binary.LE, shard)
		if err != nil {
			return nil, err
		}
		writers[index] = shard.File
	}
	w := io.MultiWriter(writers...)

	return newArchiveWriter(key[:], w, a.Files()...)
}

func (a *ShardArchive) Files() []File {
	files := make([]File, len(a.Shards))
	for i, shard := range a.Shards {
		files[i] = shard.File
	}
	return files
}

func newArchiveReader(key []byte, raw io.Reader, files ...File) (*Reader, error) {
	switch valid, err := verify(key, files[0]); {
	case err != nil:
		return nil, err
	case !valid:
		return nil, ErrInvalidArchive
	}

	buffer := bufio.NewReader(raw)
	r, err := archive.NewReader(buffer, key)

	return &Reader{
		Reader: r,
		buffer: buffer,
		files:  files,
	}, err
}

func newArchiveWriter(key []byte, raw io.Writer, files ...File) (*Writer, error) {
	tagAt, err := files[0].Seek(0, 1)
	if err != nil {
		return nil, err
	}

	buffer := bufio.NewWriter(raw)
	w, err := archive.NewWriter(buffer, key)

	return &Writer{
		Writer: w,
		buffer: buffer,
		files:  files,
		tagAt:  tagAt,
	}, err
}

func verify(key []byte, file File) (bool, error) {
	p, err := file.Seek(0, 1)
	if err != nil {
		return false, err
	}
	defer file.Seek(p, 0)
	buffer := bufio.NewReader(file)
	return archive.Verify(buffer, key)
}

func (r *Reader) Close() error {
	for _, f := range r.files {
		err := f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) Close() error {
	tag, err := w.Finish()
	if err != nil {
		return err
	}

	err = w.buffer.Flush()
	if err != nil {
		return err
	}

	for _, f := range w.files {
		_, err := f.WriteAt(tag, w.tagAt)
		if err != nil {
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

type File interface {
	io.Reader
	io.Writer
	io.WriterAt
	io.Seeker
	io.Closer
}
