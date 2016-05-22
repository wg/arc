// Copyright (C) 2016 - Will Glozer. All rights reserved.

package archive

import (
	"io"
	"io/ioutil"
)

func Verify(r io.Reader, key []byte) (bool, error) {
	archive, err := NewArchiveFromReader(r, key)
	if err != nil {
		return false, err
	}

	_, err = io.Copy(ioutil.Discard, archive)
	if err != nil {
		return false, err
	}

	return archive.Verify(), nil
}
