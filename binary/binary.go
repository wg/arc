// Copyright (C) 2016 - Will Glozer. All rights reserved.

package binary

import (
	"encoding/binary"
	"io"
	"reflect"
)

type ByteOrder binary.ByteOrder

var (
	BE ByteOrder = binary.BigEndian
	LE ByteOrder = binary.LittleEndian
)

func Write(w io.Writer, order ByteOrder, data interface{}) error {
	v := reflect.Indirect(reflect.ValueOf(data))
	t := v.Type()

	out := make([]byte, size(v, t))
	buf := out

	for i := 0; i < t.NumField(); i++ {
		v := v.Field(i)
		t := v.Type()

		if skip(v, t) {
			continue
		}

		switch t.Kind() {
		case reflect.Int8:
			buf[0] = byte(v.Int())
		case reflect.Uint8:
			buf[0] = byte(v.Uint())
		case reflect.Int16:
			order.PutUint16(buf, uint16(v.Int()))
		case reflect.Uint16:
			order.PutUint16(buf, uint16(v.Uint()))
		case reflect.Int32:
			order.PutUint32(buf, uint32(v.Int()))
		case reflect.Uint32:
			order.PutUint32(buf, uint32(v.Uint()))
		case reflect.Int64:
			order.PutUint64(buf, uint64(v.Int()))
		case reflect.Uint64:
			order.PutUint64(buf, uint64(v.Uint()))
		case reflect.Array:
			copy(buf, v.Slice(0, v.Len()).Bytes())
		}

		buf = buf[t.Size():]
	}

	_, err := w.Write(out)
	return err
}

func Read(r io.Reader, order ByteOrder, data interface{}) error {
	v := reflect.Indirect(reflect.ValueOf(data))
	t := v.Type()

	buf := make([]byte, size(v, t))

	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}

	for i := 0; i < t.NumField(); i++ {
		v := v.Field(i)
		t := v.Type()

		if skip(v, t) {
			continue
		}

		switch t.Kind() {
		case reflect.Int8:
			v.SetInt(int64(buf[0]))
		case reflect.Uint8:
			v.SetUint(uint64(buf[0]))
		case reflect.Int16:
			v.SetInt(int64(order.Uint16(buf)))
		case reflect.Uint16:
			v.SetUint(uint64(order.Uint16(buf)))
		case reflect.Int32:
			v.SetInt(int64(order.Uint32(buf)))
		case reflect.Uint32:
			v.SetUint(uint64(order.Uint32(buf)))
		case reflect.Int64:
			v.SetInt(int64(order.Uint64(buf)))
		case reflect.Uint64:
			v.SetUint(uint64(order.Uint64(buf)))
		case reflect.Array:
			reflect.Copy(v, reflect.ValueOf(buf))
		}

		buf = buf[t.Size():]
	}

	return nil
}

func size(v reflect.Value, t reflect.Type) uintptr {
	size := uintptr(0)

	for i := 0; i < t.NumField(); i++ {
		v := v.Field(i)
		t := v.Type()
		if !skip(v, t) {
			size += t.Size()
		}
	}

	return size
}

func skip(v reflect.Value, t reflect.Type) bool {
	if !v.CanSet() {
		return true
	}

	switch t.Kind() {
	case reflect.Int8, reflect.Uint8:
		return false
	case reflect.Int16, reflect.Uint16:
		return false
	case reflect.Int32, reflect.Uint32:
		return false
	case reflect.Int64, reflect.Uint64:
		return false
	case reflect.Array:
		return t.Elem().Size() != 1
	}

	return true
}
