// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"archive/tar"
	"io"
	"regexp"
	"strings"

	"github.com/wg/arc/archive"
)

type RegexFilter struct {
	Header *tar.Header
	Error  error
	regex  *regexp.Regexp
	*archive.Reader
}

func NewRegexFilter(r *archive.Reader, paths ...string) (*RegexFilter, error) {
	regex, err := regexp.Compile(strings.Join(paths, "|"))
	return &RegexFilter{
		regex:  regex,
		Reader: r,
	}, err
}

func (f *RegexFilter) Next() bool {
	for {
		switch header, err := f.Reader.Next(); {
		case err == io.EOF:
			return false
		case err != nil:
			f.Error = err
			return false
		case f.regex.MatchString(header.Name):
			f.Header = header
			return true
		}
	}
}
