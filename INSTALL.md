# arc - build instructions

arc is written in Go and all dependencies are vendored so building can be
as simple as running `go get github.com/wg/arc` or checking out the code
into a Go workspace and running `go install github.com/wg/arc`.

Building an executable that is identical to a released binary requires a
number of conditions be met:

  1. the Go toolchain version must be identical
  2. GOROOT, GOPATH and PWD must be identical
  3. the path separator character must be "/"

The Go compiler creates executables with debug information containing
filesystem paths of all packages used to build the executable as well as
the working directory. Aside from that its output is deterministic, even
when cross compiling.
