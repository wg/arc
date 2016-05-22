// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"

	"golang.org/x/crypto/ssh/terminal"
)

type Args struct {
	OperationMode        `group:"Archive Operation Mode"`
	OperationModifier    `group:"Archive Operation Modifiers"`
	KeyManagementMode    `group:"Key Management Mode"`
	SecurityOptions      `group:"Archive Security Options"`
	PasswordOptions      `group:"Password Options"`
	KeyManagementOptions `group:"Key Generation Options"`
	MiscOpts             `group:"Misc Options"`
	Positional           `positional-args:"true" required:"0"`
}

type OperationMode struct {
	Create  bool `short:"c" long:"create"  description:"create new archive"`
	List    bool `short:"t" long:"list"    description:"list archive contents"`
	Extract bool `short:"x" long:"extract" description:"extract from archive"`
}

type OperationModifier struct {
	File   string   `short:"f" long:"file"  description:"archive file"`
	Shards []string `          long:"shard" description:"archive shard"`
}

type SecurityOptions struct {
	Password  bool   `long:"password"  description:"derive key from password"`
	Key       string `long:"key"       description:"derive key from ECDH exchange"`
	Threshold int    `long:"threshold" description:"random key with SSS threshold"`
}

type KeyManagementMode struct {
	Keygen bool `long:"keygen" description:"generate key pair"`
}

type KeyManagementOptions struct {
	Private string `long:"private" description:"private key file"`
	Public  string `long:"public"  description:"public key file"`
}

type PasswordOptions struct {
	Iterations uint32 `long:"iterations" description:"argon2 iterations"`
	Memory     uint32 `long:"memory"     description:"argon2 memory use"`
}

type MiscOpts struct {
	Help    bool   `short:"h" long:"help"    description:"show this help message"`
	Verbose []bool `short:"v" long:"verbose" description:"generate verbose output"`
}

type Positional struct {
	Names []string `positional-arg-name:"names"`
}

func NewCommand() (*Cmd, error) {
	args, err := ParseArgs(os.Args[1:]...)
	if err != nil {
		return nil, err
	}

	c := &Cmd{
		Verbose: len(args.Verbose),
		Names:   args.Names,
	}

	var mode int
	switch {
	case args.Create:
		c.Op = c.Create
		mode = os.O_EXCL | os.O_CREATE | os.O_WRONLY
	case args.List:
		c.Op = c.List
		mode = os.O_RDONLY
	case args.Extract:
		c.Op = c.Extract
		mode = os.O_RDONLY
	case args.Keygen:
		c.Op = c.Keygen
	}

	switch {
	case args.Password:
		c.Archiver, err = args.PreparePasswordArchive(mode)
	case args.Key != "":
		c.Archiver, err = args.PrepareCurve448Archive(mode)
	case len(args.Shards) > 0:
		c.Archiver, err = args.PrepareShardArchive(mode)
	case args.Keygen:
		c.Public, c.Private, err = args.PrepareKeygen()
	}

	return c, err
}

func ParseArgs(arg ...string) (*Args, error) {
	args := &Args{
		PasswordOptions: PasswordOptions{
			Iterations: 3,
			Memory:     16,
		},
	}

	parser := flags.NewParser(args, flags.PassDoubleDash)
	parser.Usage = "[OPTIONS]"

	if _, err := parser.Parse(); err != nil {
		return nil, err
	}

	if args.Help {
		b := bytes.Buffer{}
		parser.WriteHelp(&b)
		return nil, errors.New(b.String())
	}

	err := args.Validate()
	return args, err
}

func (a *Args) Validate() error {
	switch {
	case !a.Create && !a.List && !a.Extract && !a.Keygen:
		return fmt.Errorf("must specify one of -c, -t, -x, --keygen")

	case a.Create && (a.List || a.Extract || a.Keygen):
		return fmt.Errorf("can't combine -c, --create with other operations")
	case a.List && (a.Create || a.Extract || a.Keygen):
		return fmt.Errorf("can't combine -t, --list with other operations")
	case a.Extract && (a.Create || a.List || a.Keygen):
		return fmt.Errorf("can't combine -x, --extract with other operations")
	case a.Keygen && (a.Create || a.Extract || a.List):
		return fmt.Errorf("can't combine --keygen with other operations")

	case a.Create && !a.Password && a.Key == "" && len(a.Shards) == 0:
		return fmt.Errorf("create requires --password, --key, or --shard")
	case a.List && !a.Password && a.Key == "" && len(a.Shards) == 0:
		return fmt.Errorf("list requires --password, --key, or --shard")
	case a.Extract && !a.Password && a.Key == "" && len(a.Shards) == 0:
		return fmt.Errorf("extract requires --password, --key, or --shard")

	case a.Password && a.Key != "":
		return fmt.Errorf("can't combine --password with --key")
	case a.Password && len(a.Shards) > 0:
		return fmt.Errorf("can't combine --password with --shard")
	case a.Key != "" && len(a.Shards) > 0:
		return fmt.Errorf("can't combine --key with --shard")

	case len(a.Shards) > 255:
		return fmt.Errorf("can't use more than 255 shards")
	case a.Create && len(a.Shards) > 0 && len(a.Shards) < 2:
		return fmt.Errorf("can't use less than 2 shards")
	case a.Create && len(a.Shards) > 0 && a.Threshold <= 1:
		return fmt.Errorf("--threshold must be > 1")
	case a.Create && len(a.Shards) > 0 && a.Threshold > len(a.Shards):
		return fmt.Errorf("--threshold must be <= %d", len(a.Shards))

	case !a.Keygen && (a.Password || a.Key != "") && a.File == "":
		return fmt.Errorf("must provide -f, --file")
	case !a.Keygen && !a.Password && a.Key == "" && a.File == "" && len(a.Shards) == 0:
		return fmt.Errorf("must provide -f, --file or --shard")
	case !a.Keygen && a.File != "" && len(a.Shards) > 0:
		return fmt.Errorf("can't combine -f, --file and --shard")

	case a.Keygen && (a.Public == "" || a.Private == ""):
		return fmt.Errorf("keygen requires --public and --private")

	case a.Create && len(a.Names) == 0:
		return fmt.Errorf("no files or directories specified")
	}

	return nil
}

func (a *Args) PreparePasswordArchive(mode int) (Archiver, error) {
	file, err := os.OpenFile(a.File, mode, 0600)
	if err != nil {
		return nil, err
	}

	password, err := ReadPassword()
	if err != nil {
		return nil, err
	}

	return NewPasswordArchive(password, a.Iterations, a.Memory, file), nil
}

func (a *Args) PrepareCurve448Archive(mode int) (Archiver, error) {
	var publicKey PublicKey
	var privateKey PrivateKey
	var err error

	if mode&os.O_CREATE == os.O_CREATE {
		err = a.LoadPublicKey(&publicKey)
	} else {
		err = a.LoadPrivateKey(&privateKey)
	}

	if err != nil {
		return nil, fmt.Errorf("file %s: %s", a.Key, err)
	}

	file, err := os.OpenFile(a.File, mode, 0600)
	if err != nil {
		return nil, err
	}

	return NewCurve448Archive(&publicKey, &privateKey, file), nil
}

func (a *Args) PrepareShardArchive(mode int) (Archiver, error) {
	files := make([]File, len(a.Shards))
	for i, path := range a.Shards {
		file, err := os.OpenFile(path, mode, 0600)
		if err != nil {
			return nil, err
		}
		files[i] = file
	}
	return NewShardArchive(a.Threshold, files), nil
}

func (a *Args) PrepareKeygen() (public *KeyContainer, private *KeyContainer, err error) {
	mode := os.O_EXCL | os.O_CREATE | os.O_WRONLY

	public, err = a.OpenPublicKeyContainer(a.Public, mode)
	if err != nil {
		return nil, nil, fmt.Errorf("can't create public key: %s", err)
	}

	private, err = a.OpenPrivateKeyContainer(a.Private, mode)
	if err != nil {
		return nil, nil, fmt.Errorf("can't create private key: %s", err)
	}

	return public, private, err
}

func (a *Args) LoadPublicKey(key *PublicKey) error {
	c, err := a.OpenPublicKeyContainer(a.Key, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ReadPublicKey(key)
}

func (a *Args) LoadPrivateKey(key *PrivateKey) error {
	c, err := a.OpenPrivateKeyContainer(a.Key, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ReadPrivateKey(key)
}

func (a *Args) OpenPublicKeyContainer(path string, mode int) (*KeyContainer, error) {
	file, err := os.OpenFile(path, mode, 0600)
	if err != nil {
		return nil, err
	}
	return NewKeyContainer(file, []byte(""), 1, 8), nil
}

func (a *Args) OpenPrivateKeyContainer(path string, mode int) (*KeyContainer, error) {
	file, err := os.OpenFile(path, mode, 0600)
	if err != nil {
		return nil, err
	}

	password, err := ReadPassword()
	if err != nil {
		return nil, err
	}

	return NewKeyContainer(file, password, a.Iterations, a.Memory), nil
}

func ReadPassword() ([]byte, error) {
	fmt.Print("password: ")
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	return b, err
}
