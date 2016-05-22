// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"fmt"
	"os"

	"github.com/wg/arc/archive"
)

type Cmd struct {
	Op       interface{}
	Archiver Archiver
	Verbose  int
	Names    []string
	Private  *KeyContainer
	Public   *KeyContainer
}

func main() {
	c, err := NewCommand()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	switch op := c.Op.(type) {
	case func(*archive.Writer, ...string) error:
		arc := c.createArchive()
		err = op(arc.Writer, c.Names...)
		defer arc.Close()
	case func(*RegexFilter) error:
		arc, filter := c.filterArchive()
		err = op(filter)
		defer arc.Close()
	case func(*KeyContainer, *KeyContainer) error:
		err = op(c.Public, c.Private)
		defer c.Public.Close()
		defer c.Private.Close()
	}

	if err != nil {
		c.Fatal(err)
	}
}

func (c *Cmd) createArchive() *Writer {
	arc, err := c.Archiver.Writer()
	if err != nil {
		c.Fatal(err)
	}
	return arc
}

func (c *Cmd) filterArchive() (*Reader, *RegexFilter) {
	arc, err := c.Archiver.Reader()
	if err != nil {
		c.Fatal(err)
	}

	f, err := NewRegexFilter(arc.Reader, c.Names...)
	if err != nil {
		c.Fatal(err)
	}

	return arc, f
}

func (c *Cmd) Fatal(v ...interface{}) {
	fmt.Println(v...)
	os.Exit(1)
}
