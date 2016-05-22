// Copyright (C) 2016 - Will Glozer. All rights reserved.

package archive

import (
	"archive/tar"
	"errors"
	"io"

	"github.com/klauspost/compress/gzip"
)

var (
	ErrShortCopy = errors.New("archive: short copy")
)

type Writer struct {
	archiver   *tar.Writer
	compressor *gzip.Writer
	archive    *Archive
}

func NewWriter(w io.Writer, key []byte) (*Writer, error) {
	archive, err := NewArchiveForWriter(w, key)
	if err != nil {
		return nil, err
	}

	compressor := gzip.NewWriter(archive)
	archiver := tar.NewWriter(compressor)

	return &Writer{
		archiver:   archiver,
		compressor: compressor,
		archive:    archive,
	}, nil
}

func (w *Writer) Add(header *tar.Header) error {
	return w.archiver.WriteHeader(header)
}

func (w *Writer) Copy(r io.Reader, size int64) error {
	switch n, err := io.Copy(w.archiver, r); {
	case err != nil:
		return err
	case n < size:
		return ErrShortCopy
	}
	return w.archiver.Flush()
}

func (w *Writer) Finish() ([]byte, error) {
	if err := w.archiver.Close(); err != nil {
		return nil, err
	}

	if err := w.compressor.Close(); err != nil {
		return nil, err
	}

	return w.archive.Tag(nil), nil
}
