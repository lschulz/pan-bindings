//go:build debug

package main

import (
	"fmt"
	"os"
)

func debugPrintf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a)
}
