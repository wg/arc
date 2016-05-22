// Copyright (C) 2016 - Will Glozer. All rights reserved.

package archive

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"testing"
)

func TestCreateArchive(t *testing.T) {
	entries := []*tar.Header{
		{Name: "foo", Size: 0},
		{Name: "bar", Size: 1<<16 - 1},
		{Name: "baz", Size: 64},
	}
	key := randomKey()

	buf, dat, err := createArchive(key, entries)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(buf, key)
	if err != nil {
		t.Fatal(err)
	}

	for i, e := range entries {
		switch next, err := r.Next(); {
		case err != nil:
			t.Fatal(err)
		case e.Name != next.Name:
			t.Fatalf("expected entry name %s got %s", e.Name, next.Name)
		case e.Size != next.Size:
			t.Fatalf("expected entry size %d got %d", e.Size, next.Size)
		}

		switch b, err := ioutil.ReadAll(r); {
		case err != nil:
			t.Fatal(err)
		case int(e.Size) != len(b):
			t.Fatalf("expected to read %d bytes got %d", e.Size, len(b))
		case !bytes.Equal(b, dat[i]):
			t.Fatalf("expected content '%v' got '%v'", b, dat[i])
		}
	}

	if !r.Verify() {
		t.Fatal("archive verify failed")
	}
}

func TestVerifyArchive(t *testing.T) {
	entries := []*tar.Header{
		{Name: "foo", Size: 32},
		{Name: "bar", Size: 64},
	}
	key := randomKey()

	buf, _, err := createArchive(key, entries)
	if err != nil {
		t.Fatal(err)
	}

	if valid, _ := Verify(buf, key); !valid {
		t.Fatal("archive verify failed")
	}
}

func TestVerifyFailWrongKey(t *testing.T) {
	entries := []*tar.Header{
		{Name: "foo", Size: 32},
		{Name: "bar", Size: 64},
	}
	key := randomKey()

	buf, _, err := createArchive(key, entries)
	if err != nil {
		t.Fatal(err)
	}

	key[0] = ^key[0]

	if valid, _ := Verify(buf, key); valid {
		t.Fatal("verified invalid archive")
	}
}

func TestVerifyFailByteFlip(t *testing.T) {
	entries := []*tar.Header{
		{Name: "foo", Size: 32},
		{Name: "bar", Size: 64},
	}
	key := randomKey()

	buf, _, err := createArchive(key, entries)
	if err != nil {
		t.Fatal(err)
	}

	archive := buf.Bytes()
	for i, b := range archive {
		archive[i] = ^archive[i]

		r := bytes.NewReader(archive)
		if valid, _ := Verify(r, key); valid {
			t.Fatal("verified invalid archive at", i)
		}

		archive[i] = b
	}
}

func TestWriterInvariants(t *testing.T) {
	_, _, err := createArchive(make([]byte, 31), nil)
	if err == nil {
		t.Fatalf("created archive with 31 byte key")
	}
}

func createArchive(key []byte, entries []*tar.Header) (*Buffer, [][]byte, error) {
	buf := &Buffer{}

	arc, err := NewWriter(buf, key)
	if err != nil {
		return nil, nil, err
	}

	dat := make([][]byte, len(entries))

	for i, e := range entries {
		err := arc.Add(e)
		if err != nil {
			return nil, nil, err
		}

		dat[i] = make([]byte, e.Size)
		_, err = rand.Read(dat[i])
		if err != nil {
			return nil, nil, err
		}

		err = arc.Copy(bytes.NewReader(dat[i]), e.Size)
		if err != nil {
			return nil, nil, err
		}
	}

	tag, _ := arc.Finish()
	copy(buf.Bytes()[0:16], tag)

	return buf, dat, nil
}

type Buffer struct {
	bytes.Buffer
}

func randomKey() []byte {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panic(err)
	}
	return key
}
