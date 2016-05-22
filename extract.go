// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wg/arc/archive"
)

func (c *Cmd) Extract(arc *RegexFilter) error {
	mtimes := map[string]time.Time{}

	for arc.Next() {
		h := arc.Header

		name := h.Name
		mode := os.FileMode(h.Mode)

		var err error
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			err = extract(name, mode, h.Size, arc)
		case tar.TypeDir:
			err = os.Mkdir(name, mode)
		case tar.TypeSymlink:
			err = os.Symlink(h.Linkname, name)
		}

		var action string
		switch {
		case os.IsExist(err):
			action = "-"
		case err != nil:
			return err
		default:
			action = "x"
		}

		if c.Verbose > 0 {
			fmt.Println(action, name)
		}

		mtimes[name] = h.ModTime
	}

	switch {
	case arc.Error != nil:
		return arc.Error
	case !arc.Verify():
		return ErrVerifyFailed
	}

	ctime := time.Now()
	for name, mtime := range mtimes {
		err := os.Chtimes(name, ctime, mtime)
		if err != nil {
			return err
		}
	}

	return nil
}

func extract(path string, mode os.FileMode, size int64, r io.Reader) error {
	err := os.MkdirAll(filepath.Dir(path), 0)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_EXCL|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()

	switch n, err := io.Copy(f, r); {
	case err != nil:
		return err
	case n < size:
		return archive.ErrShortCopy
	}

	return nil
}
