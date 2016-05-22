// Copyright (C) 2016 - Will Glozer. All rights reserved.

package archive

import (
	"archive/tar"
	"compress/gzip"
	"io"
)

type Reader struct {
	archiver   *tar.Reader
	compressor *gzip.Reader
	archive    *Archive
}

func NewReader(r io.Reader, key []byte) (*Reader, error) {
	archive, err := NewArchiveFromReader(r, key)
	if err != nil {
		return nil, err
	}

	compressor, err := gzip.NewReader(archive)
	if err != nil {
		return nil, err
	}

	archiver := tar.NewReader(compressor)

	return &Reader{
		archiver:   archiver,
		compressor: compressor,
		archive:    archive,
	}, nil
}

func (r *Reader) Next() (*tar.Header, error) {
	return r.archiver.Next()
}

func (r *Reader) Read(b []byte) (int, error) {
	return r.archiver.Read(b)
}

func (r *Reader) Verify() bool {
	return r.archive.Verify()
}
