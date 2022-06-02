package main

import (
	"flag"
	"fmt"
)

const Version = "v0.9.9"
const banner = `

fjnttre kff fpnaare
`

// showBanner is used to show the banner to the user
func ShowBanner() {
	fmt.Printf("%s\t\t\t\t%s\n", banner, Version)
	fmt.Printf("\t\t Security | Netease\n")
	fmt.Printf("A powerful Swagger UI Dom Xss Scanner scanner for security engineer.\n\n")
}

type Options struct {
	MaxConcurrency int
	ScanFile       string
	ResultDir      string
}

func ParseOptions() *Options {
	options := &Options{}

	flag.IntVar(&options.MaxConcurrency, "m", 3, "Max concurrency. default 3")
	flag.StringVar(&options.ScanFile, "f", "url.txt", "Scan file path. default url.txt")
	flag.StringVar(&options.ResultDir, "o", "result", "scan result dir. default result")

	flag.Parse()

	ShowBanner()

	return options
}
