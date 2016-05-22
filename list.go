// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"os"
)

var (
	ErrVerifyFailed = errors.New("archive: verify failed")
	ErrNoEntryFound = errors.New("archive: no entry found")
)

func (c *Cmd) List(arc *RegexFilter) error {
	matches := 0

	for arc.Next() {
		h := arc.Header
		switch {
		case c.Verbose > 0:
			const layout = "%s  %-6d %-6d %8s %s  %s\n"
			mode := mode(h)
			size := size(h)
			date := h.ModTime.Format("2006-01-02 15:04")
			name := name(h)
			fmt.Printf(layout, mode, h.Uid, h.Gid, size, date, name)
		default:
			fmt.Println(h.Name)
		}
		matches++
	}

	switch {
	case arc.Error != nil:
		return arc.Error
	case !arc.Verify():
		return ErrVerifyFailed
	case matches == 0:
		return ErrNoEntryFound
	}

	return nil
}

func mode(h *tar.Header) string {
	mode := os.FileMode(h.Mode)
	switch h.Typeflag {
	case tar.TypeDir:
		mode |= os.ModeDir
	case tar.TypeSymlink:
		mode |= os.ModeSymlink
	}
	return mode.String()
}

func size(h *tar.Header) string {
	if h.Size == 0 {
		return "0"
	}
	return ByteSize(h.Size).String()
}

func name(h *tar.Header) string {
	name := h.Name
	if h.Typeflag == tar.TypeSymlink {
		name += " -> " + h.Linkname
	}
	return name
}
