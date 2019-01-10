package main

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"golang.org/x/oauth2/google"

	"google.golang.org/api/dns/v1"
)

func process(cli *dns.Service, domain string, text string) error {
	if len(domain) == 0 {
		return errors.New("domainName is empty.")
	}

	fqdn := domain + "."

	project := os.Getenv("GCE_PROJECT")
	managedZone := os.Getenv("GCE_MANAGED_ZONE")

	if len(project) == 0 {
		return errors.New("GCE_PROJECT is empty.")
	}

	if len(managedZone) == 0 {
		return errors.New("GCE_MANAGED_ZONE is empty.")
	}

	list, err := cli.ResourceRecordSets.List(project, managedZone).Name(fqdn).Type("TXT").Do()
	if err != nil {
		return err
	}

	change := &dns.Change{}

	if len(text) > 0 {
		change.Additions = []*dns.ResourceRecordSet{
			&dns.ResourceRecordSet{
				Name:    fqdn,
				Rrdatas: []string{text},
				Ttl:     10,
				Type:    "TXT",
			},
		}
	}

	if len(list.Rrsets) > 0 {
		change.Deletions = list.Rrsets
	}

	if len(change.Additions) == 0 && len(change.Deletions) == 0 {
		return nil
	}

	res, err := cli.Changes.Create(project, managedZone, change).Do()
	if err != nil {
		return err
	}

	for res.Status == "pending" {
		time.Sleep(time.Second)

		res, err = cli.Changes.Get(project, managedZone, res.Id).Do()
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	http, err := google.DefaultClient(context.Background(), dns.NdevClouddnsReadwriteScope)
	if err != nil {
		log.Fatal(err)
	}

	cli, err := dns.New(http)
	if err != nil {
		log.Fatal(err)
	}

	domain := ""
	text := ""

	if len(os.Args) > 1 {
		domain = os.Args[1]
	}

	if len(os.Args) > 2 {
		text = os.Args[2]
	}

	err = process(cli, domain, text)
	if err != nil {
		log.Fatal(err)
	}
}
