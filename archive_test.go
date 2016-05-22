// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"
	"testing"

	"github.com/codahale/sss"
	"github.com/magical/argon2"
	"github.com/wg/arc/archive"
)

var entries = []*tar.Header{
	{Name: "foo", Size: 0},
	{Name: "bar", Size: 1<<16 - 1},
	{Name: "baz", Size: 64},
}

func TestPasswordArchive(t *testing.T) {
	arc := NewPasswordArchive([]byte("secret"), 1, 8, &Buffer{})
	dat := createArchive(t, arc)
	verifyArchive(t, arc, dat)
}

func TestPasswordArchiveKey(t *testing.T) {
	var (
		password   = []byte("secret")
		iterations = 1
		memory     = 8
	)

	buf := &Buffer{}
	arc := NewPasswordArchive(password, uint32(iterations), uint32(memory), buf)
	createArchive(t, arc)

	buf.Rewind()
	buf.Seek(2+4+4+32, 0)

	key, err := argon2.Key(password, arc.Salt[:], int(iterations), 1, int64(memory), KeySize)
	if err != nil {
		t.Fatal("password key derivation failed", err)
	}

	if valid, err := archive.Verify(buf, key); !valid || err != nil {
		t.Fatal("password archive key incorrect")
	}
}

func TestPasswordArchiveFormat(t *testing.T) {
	buf := &Buffer{}
	arc := NewPasswordArchive([]byte("secret"), 2, 16, buf)
	createArchive(t, arc)

	if binary.LittleEndian.Uint32(buf.buffer[2:6]) != arc.Iterations {
		t.Fatal("serialized iterations incorrect")
	}

	if binary.LittleEndian.Uint32(buf.buffer[6:10]) != arc.Memory {
		t.Fatal("serialized memory incorrect")
	}

	if !bytes.Equal(buf.buffer[10:42], arc.Salt[:]) {
		t.Fatal("serialized salt incorrect")
	}
}

func TestWrongPassword(t *testing.T) {
	arc := NewPasswordArchive([]byte("secret"), 1, 8, &Buffer{})
	createArchive(t, arc)
	arc.Password = []byte("terces")
	ensureInvalid(t, arc)
}

func TestCurve448Archive(t *testing.T) {
	public, private := keypair(t)
	arc := NewCurve448Archive(public, private, &Buffer{})
	dat := createArchive(t, arc)
	verifyArchive(t, arc, dat)
}

func TestCurve448ArchiveKey(t *testing.T) {
	public, private := keypair(t)
	buf := &Buffer{}
	arc := NewCurve448Archive(public, nil, buf)
	createArchive(t, arc)

	buf.Rewind()
	buf.Seek(2+56, 0)

	key, err := ComputeSharedKey(&arc.Ephemeral, private, KeySize)
	if err != nil {
		t.Fatal("curve448 key derivation failed", err)
	}

	if valid, err := archive.Verify(buf, key); !valid || err != nil {
		t.Fatal("curve448 archive key incorrect")
	}
}

func TestCurve448ArchiveFormat(t *testing.T) {
	public, private := keypair(t)
	buf := &Buffer{}
	arc := NewCurve448Archive(public, private, buf)
	createArchive(t, arc)

	if !bytes.Equal(buf.buffer[2:58], arc.Ephemeral[:]) {
		t.Fatal("serialized ephemeral public key incorrect")
	}
}

func TestWrongPrivateKey(t *testing.T) {
	public, _ := keypair(t)
	_, private := keypair(t)
	arc := NewCurve448Archive(public, private, &Buffer{})
	createArchive(t, arc)
	ensureInvalid(t, arc)
}

func TestShardArchive(t *testing.T) {
	arc := NewShardArchive(2, buffers(3))
	dat := createArchive(t, arc)
	verifyArchive(t, arc, dat)
}

func TestShardArchiveKey(t *testing.T) {
	arc := NewShardArchive(2, buffers(3))
	createArchive(t, arc)

	shares := map[byte][]byte{}
	for _, shard := range arc.Shards {
		shares[shard.ID] = shard.Share[:]
	}
	key := sss.Combine(shares)

	for _, shard := range arc.Shards {
		buf := shard.File.(*Buffer)
		buf.Rewind()
		buf.Seek(2+1+KeySize, 0)

		if valid, err := archive.Verify(buf, key); !valid || err != nil {
			t.Fatal("shard archive key incorrect")
		}
	}
}

func TestShardArchiveFormat(t *testing.T) {
	arc := NewShardArchive(2, buffers(3))
	createArchive(t, arc)

	for _, shard := range arc.Shards {
		buf := shard.File.(*Buffer)

		if buf.buffer[2] != shard.ID {
			t.Fatal("serialized shard ID incorrect")
		}

		if !bytes.Equal(buf.buffer[3:3+KeySize], shard.Share[:]) {
			t.Fatal("serialized shard share incorrect")
		}
	}
}

func TestMissingShard(t *testing.T) {
	arc := NewShardArchive(2, buffers(2))
	createArchive(t, arc)
	arc.Shards = arc.Shards[:1]
	ensureInvalid(t, arc)
}

func TestArchiveHeader(t *testing.T) {
	public, private := keypair(t)
	var (
		password = NewPasswordArchive([]byte("secret"), 1, 8, &Buffer{})
		curve448 = NewCurve448Archive(public, private, &Buffer{})
		shard    = NewShardArchive(2, buffers(2))
	)

	createArchive(t, password)
	createArchive(t, curve448)
	createArchive(t, shard)

	switch {
	case password.File.(*Buffer).buffer[0] != Version:
		t.Fatal("wrong version in password archive")
	case password.File.(*Buffer).buffer[1] != Password:
		t.Fatal("wrong type in password archive")
	case curve448.File.(*Buffer).buffer[0] != Version:
		t.Fatal("wrong version in curve448 archive")
	case curve448.File.(*Buffer).buffer[1] != Curve448:
		t.Fatal("wrong type in curve448 archive")
	}

	for _, s := range shard.Shards {
		switch {
		case s.File.(*Buffer).buffer[0] != Version:
			t.Fatal("wrong version in shard archive")
		case s.File.(*Buffer).buffer[1] != Shard:
			t.Fatal("wrong type in shard archive")

		}
	}
}

func TestWrongArchiveType(t *testing.T) {
	public, private := keypair(t)
	var (
		password = NewPasswordArchive([]byte("secret"), 1, 8, &Buffer{})
		curve448 = NewCurve448Archive(public, private, &Buffer{})
		shard    = NewShardArchive(2, buffers(2))
	)

	createArchive(t, password)
	createArchive(t, curve448)
	createArchive(t, shard)

	ensureInvalidType(t, NewPasswordArchive([]byte("secret"), 1, 8, curve448.File))
	ensureInvalidType(t, NewPasswordArchive([]byte("secret"), 1, 8, shard.Shards[0].File))
	ensureInvalidType(t, NewCurve448Archive(public, private, password.File))
	ensureInvalidType(t, NewCurve448Archive(public, private, shard.Shards[0].File))
	ensureInvalidType(t, NewShardArchive(2, []File{password.File}))
	ensureInvalidType(t, NewShardArchive(2, []File{curve448.File}))
}

func createArchive(t *testing.T, a Archiver) [][]byte {
	dat := make([][]byte, len(entries))

	writer, err := a.Writer()
	if err != nil {
		t.Fatal(err)
	}

	for i, e := range entries {
		err := writer.Add(e)
		if err != nil {
			t.Fatal(err)
		}

		dat[i] = make([]byte, e.Size)
		_, err = rand.Read(dat[i])
		if err != nil {
			t.Fatal(err)
		}

		err = writer.Copy(bytes.NewReader(dat[i]), e.Size)
		if err != nil {
			t.Fatal(err)
		}
	}

	writer.Close()

	switch a := a.(type) {
	case *PasswordArchive:
		a.File.(*Buffer).Rewind()
	case *Curve448Archive:
		a.File.(*Buffer).Rewind()
	case *ShardArchive:
		for _, s := range a.Shards {
			s.File.(*Buffer).Rewind()
		}
	}

	return dat
}

func verifyArchive(t *testing.T, a Archiver, dat [][]byte) {
	reader, err := a.Reader()
	if err != nil {
		t.Fatal(err)
	}

	for i, e := range entries {
		switch next, err := reader.Next(); {
		case err != nil:
			t.Fatal(err)
		case e.Name != next.Name:
			t.Fatalf("expected entry name %s got %s", e.Name, next.Name)
		case e.Size != next.Size:
			t.Fatalf("expected entry size %d got %d", e.Size, next.Size)
		}

		switch b, err := ioutil.ReadAll(reader); {
		case err != nil:
			t.Fatal(err)
		case int(e.Size) != len(b):
			t.Fatalf("expected to read %d bytes got %d", e.Size, len(b))
		case !bytes.Equal(b, dat[i]):
			t.Fatalf("expected content '%v' got '%v'", b, dat[i])
		}
	}

	if !reader.Verify() {
		t.Fatalf("archive verify failed")
	}
}

func ensureInvalid(t *testing.T, a Archiver) {
	switch _, err := a.Reader(); {
	case err != nil && err != ErrInvalidArchive:
		t.Fatal("error validating archive", err)
	case err == nil:
		t.Fatal("invalid archive verified")
	}
}

func ensureInvalidType(t *testing.T, a Archiver) {
	switch _, err := a.Reader(); {
	case err == ErrPasswordArchive:
	case err == ErrCurve448Archive:
	case err == ErrShardArchive:
	case err != nil:
		t.Fatal("error checking archive type", err)
	case err == nil:
		t.Fatal("invalid archive type accepted")
	}

	switch a := a.(type) {
	case *PasswordArchive:
		a.File.(*Buffer).Rewind()
	case *Curve448Archive:
		a.File.(*Buffer).Rewind()
	case *ShardArchive:
		for _, s := range a.Shards {
			s.File.(*Buffer).Rewind()
		}
	}
}

func keypair(t *testing.T) (*PublicKey, *PrivateKey) {
	public, private, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func buffers(n int) []File {
	files := make([]File, n)
	for i := range files {
		files[i] = &Buffer{}
	}
	return files
}

type Buffer struct {
	buffer []byte
	offset int
}

func (b *Buffer) Read(p []byte) (int, error) {
	s := b.buffer[b.offset:]
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s)
	b.offset += n
	return n, nil
}

func (b *Buffer) Write(p []byte) (int, error) {
	n := len(p)
	b.buffer = append(b.buffer, p...)
	b.offset += n
	return n, nil
}

func (b *Buffer) WriteAt(p []byte, off int64) (int, error) {
	n := len(p)
	m := int(off)
	copy(b.buffer[m:m+n], p)
	return n, nil
}

func (b *Buffer) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		b.offset = int(offset)
	case 1:
		b.offset += int(offset)
	case 2:
		b.offset = len(b.buffer) - int(offset)
	}
	return int64(b.offset), nil
}

func (b *Buffer) Close() error {
	return nil
}

func (b *Buffer) Rewind() {
	b.offset = 0
}
