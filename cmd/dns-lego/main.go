package main

import (
	"errors"
	"log"
	"os"

	"github.com/xenolf/lego/providers/dns"
)

func main() {
	name := os.Getenv("LEGO_DNS_PROVIDER")

	p, err := dns.NewDNSChallengeProviderByName(name)
	if err != nil {
		log.Fatal(err)
	}

	var args []string
	cleanup := false

	for _, v := range os.Args[1:] {
		if v == "--cleanup" {
			cleanup = true
		} else {
			args = append(args, v)
		}
	}

	if len(args) != 3 {
		log.Fatal(errors.New("invlid.args"))
	}

	if !cleanup {
		err = p.Present(args[0], args[1], args[2])
	} else {
		err = p.CleanUp(args[0], args[1], args[2])
	}

	if err != nil {
		log.Fatal(err)
	}
}
