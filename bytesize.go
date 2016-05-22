// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "fmt"

type ByteSize float64

const (
	_           = iota // ignore first value by assigning to blank identifier
	KB ByteSize = 1 << (10 * iota)
	MB
	GB
	TB
	PB
	EB
	ZB
	YB
)

func (b ByteSize) String() string {
	switch {
	case b >= YB:
		return fmt.Sprintf("%.2fY", b/YB)
	case b >= ZB:
		return fmt.Sprintf("%.2fZ", b/ZB)
	case b >= EB:
		return fmt.Sprintf("%.2fE", b/EB)
	case b >= PB:
		return fmt.Sprintf("%.2fP", b/PB)
	case b >= TB:
		return fmt.Sprintf("%.2fT", b/TB)
	case b >= GB:
		return fmt.Sprintf("%.2fG", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.2fM", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.2fK", b/KB)
	}
	return fmt.Sprintf("%.2fB", b)
}
