// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/wg/arc/archive"
)

func (c *Cmd) Create(arc *archive.Writer, names ...string) error {
	headers, errors := Scan(names)
	for header := range headers {
		name := header.Name
		size := header.Size

		err := arc.Add(header)
		if err != nil {
			return err
		}

		if header.Typeflag == tar.TypeReg {
			r, err := os.Open(name)
			if err != nil {
				return err
			}

			err = arc.Copy(r, size)
			r.Close()

			if err != nil {
				return err
			}
		}

		if c.Verbose > 0 {
			fmt.Println("a", name)
		}
	}

	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}

func Scan(names []string) (<-chan *tar.Header, <-chan error) {
	headers := make(chan *tar.Header, 64)
	errors := make(chan error)

	go func() {
		err := scan(names, headers)
		close(headers)
		if err != nil {
			errors <- err
		}
	}()

	return headers, errors
}

func scan(names []string, headers chan<- *tar.Header) error {
	for _, name := range names {
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}

		mode := info.Mode()
		link := ""

		if !mode.IsRegular() && mode&(os.ModeDir|os.ModeSymlink) == 0 {
			continue
		}

		if mode&os.ModeSymlink != 0 {
			link, err = os.Readlink(name)
			if err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}

		header.Name = name
		headers <- header

		if mode.IsDir() {
			dir, err := os.Open(name)
			if err != nil {
				return err
			}

			for err == nil {
				names, err = dir.Readdirnames(64)
				if err != nil {
					break
				}

				for i, n := range names {
					names[i] = filepath.Join(name, n)
				}

				err = scan(names, headers)
			}
			dir.Close()

			if err != nil && err != io.EOF {
				return err
			}
		}
	}
	return nil
}
