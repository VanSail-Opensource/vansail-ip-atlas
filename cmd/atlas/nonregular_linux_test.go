package main

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCommandsRejectDevicesAndFIFOWithoutOpening(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "input.via3")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"/dev/zero", fifo} {
		for _, command := range []string{"inspect", "compile-facts"} {
			t.Run(command+"-"+filepath.Base(input), func(t *testing.T) {
				args := []string{"inspect", "-file", input}
				if command == "compile-facts" {
					args = []string{"compile-facts", "-input", input, "-workspace", t.TempDir()}
				}
				finished := make(chan error, 1)
				go func() { finished <- run(context.Background(), args) }()
				select {
				case err := <-finished:
					if err == nil {
						t.Fatal("nonregular input accepted")
					}
				case <-time.After(time.Second):
					t.Fatal("nonregular input blocked before regular-file validation")
				}
			})
		}
	}
}
