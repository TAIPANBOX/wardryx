//go:build unix

package sloburn

import "syscall"

// makeFIFO makes a named pipe, the thing a reader that opens before it checks
// would block on.
func makeFIFO(path string) error { return syscall.Mkfifo(path, 0o600) }
