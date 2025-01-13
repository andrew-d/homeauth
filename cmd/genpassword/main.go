package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"

	"github.com/andrew-d/homeauth/pwhash"
)

var (
	time    = flag.Uint("time", 2, "the execution time parameter for argon2id")
	memory  = flag.Uint("memory", 512*1024, "the memory parameter for argon2id")
	threads = flag.Uint("threads", 2, "the number of threads to use for argon2id")

	stdin = flag.Bool("stdin", false, "read password from stdin")
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 && !*stdin {
		fmt.Printf("Usage: %s [flags] password\n", os.Args[0])
		fmt.Printf("       %s [flags] -stdin\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var (
		password []byte
		err      error
	)
	if *stdin {
		password, err = io.ReadAll(os.Stdin)
	} else {
		password = []byte(flag.Arg(0))
	}
	if err != nil {
		log.Fatalf("failed to read password from stdin: %v", err)
	}

	if *time > math.MaxUint32 {
		log.Fatalf("time parameter is too large")
	} else if *memory > math.MaxUint32 {
		log.Fatalf("memory parameter is too large")
	} else if *threads > math.MaxUint8 {
		log.Fatalf("threads parameter is too large")
	}

	hasher := pwhash.New(uint32(*time), uint32(*memory), uint8(*threads))
	hash := hasher.Hash(password)
	fmt.Println(string(hash))
}
