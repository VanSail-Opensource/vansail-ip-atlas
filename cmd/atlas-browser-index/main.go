// Command atlas-browser-index derives or independently verifies the browser's
// bounded routing directory from the complete native release.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"vansail-ip-atlas/internal/via3"
)

func main() {
	atlas := flag.String("atlas", "", "immutable atlas directory")
	out := flag.String("out", "", "dedicated index directory")
	verify := flag.String("verify", "", "recompute and check against the pinned root digest")
	flag.Parse()
	if *atlas == "" || *out == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	if *verify == "" {
		var root string
		root, err = via3.GenerateBrowserIndex(ctx, *atlas, *out)
		if err == nil {
			fmt.Println(root)
		}
	} else {
		err = via3.VerifyBrowserIndex(ctx, *atlas, *out, *verify)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
