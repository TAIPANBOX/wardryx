//go:build !unix

package sloburn

import "errors"

func makeFIFO(string) error { return errors.New("no named pipes here") }
