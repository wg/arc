// Copyright (C) 2016 - Will Glozer. All rights reserved.

package binary

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestBinaryArray(t *testing.T) {
	type Values struct {
		Byte  byte
		Array [3]byte
		Int64 int64
	}

	in := &Values{1, [3]byte{2, 3, 4}, 0xAC00BD00}

	buf := &bytes.Buffer{}
	out := &Values{}

	if err := Write(buf, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}

	if err := Read(buf, binary.LittleEndian, out); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip serialization failed")
	}
}

func TestBinaryMinMax(t *testing.T) {
	type Values struct {
		MinInt8   int8
		MaxInt8   int8
		MaxUint8  uint8
		MinInt16  int16
		MaxInt16  int16
		MaxUint16 uint16
		MinInt32  int32
		MaxInt32  int32
		MaxUint32 uint32
		MinInt64  int64
		MaxInt64  int64
		MaxUint64 uint64
	}

	in := &Values{
		MinInt8:   math.MinInt8,
		MaxInt8:   math.MaxInt8,
		MaxUint8:  1<<8 - 1,
		MinInt16:  math.MinInt16,
		MaxInt16:  math.MaxInt16,
		MaxUint16: 1<<16 - 1,
		MinInt32:  math.MinInt32,
		MaxInt32:  math.MaxInt32,
		MaxUint32: 1<<32 - 1,
		MinInt64:  math.MinInt64,
		MaxInt64:  math.MaxInt64,
		MaxUint64: 1<<64 - 1,
	}

	out := &Values{}
	buf := &bytes.Buffer{}

	if err := Write(buf, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}

	if err := Read(buf, binary.LittleEndian, out); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip serialization failed")
	}
}

func TestBinaryByteOrder(t *testing.T) {
	type Values struct {
		Uint16 uint16
		Uint32 uint32
		Uint64 uint64
	}

	in := &Values{
		Uint16: 0x1234,
		Uint32: 0x12345678,
		Uint64: 0x1234567890ABCDEF,
	}

	little := []byte{0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12}

	buf := &bytes.Buffer{}

	if err := Write(buf, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes()[0:2], little[6:8]) {
		t.Fatalf("uint16 little endian incorrect")
	}

	if !bytes.Equal(buf.Bytes()[2:6], little[4:8]) {
		t.Fatalf("uint32 little endian incorrect")
	}

	if !bytes.Equal(buf.Bytes()[6:14], little[0:8]) {
		t.Fatalf("uint64 little endian incorrect")
	}
	buf.Reset()

	big := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}

	if err := Write(buf, binary.BigEndian, in); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes()[0:2], big[0:2]) {
		t.Fatalf("uint16 big endian incorrect")
	}

	if !bytes.Equal(buf.Bytes()[2:6], big[0:4]) {
		t.Fatalf("uint32 big endian incorrect")
	}

	if !bytes.Equal(buf.Bytes()[6:14], big[0:8]) {
		t.Fatalf("uint64 big endian incorrect")
	}

}

func TestBinarySkip(t *testing.T) {
	type Values struct {
		A byte
		B string
		C int32
		D []byte
		e byte
	}

	in := &Values{1, "foo", 0xABCDEF, []byte("bar"), 2}

	out := &Values{}
	buf := &bytes.Buffer{}

	if err := Write(buf, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}

	if err := Read(buf, binary.LittleEndian, out); err != nil {
		t.Fatal(err)
	}

	in.B = ""
	in.D = nil
	in.e = 0

	if !reflect.DeepEqual(in, out) {
		t.Fatal("round trip serialization failed")
	}
}
