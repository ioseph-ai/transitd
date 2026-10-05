// Command transitd is the per-router transit management agent.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// version is set by goreleaser ldflags.
var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/transitd.yaml", "path to config file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println("transitd", version)
		return
	}
	if _, err := os.Stat(*cfgPath); err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("transitd %s starting (config %s) — agent runtime not yet wired; see docs/design.md", version, *cfgPath)
}
