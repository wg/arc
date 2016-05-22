// Copyright (C) 2016 - Will Glozer. All rights reserved.

package main

func (c *Cmd) Keygen(puc *KeyContainer, prc *KeyContainer) error {
	public, private, err := GenerateKeypair()
	if err != nil {
		return err
	}

	if err = puc.WritePublicKey(public); err != nil {
		return err
	}

	if err = prc.WritePrivateKey(private); err != nil {
		return err
	}

	return nil
}
