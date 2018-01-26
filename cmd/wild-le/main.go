package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/noumia/acme"
	"github.com/urfave/cli"
)

const EP = "https://acme-staging-v02.api.letsencrypt.org/directory"

/* */

func readKey(path string) (crypto.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", path)
	}

	if d.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(d.Bytes)
	}

	return nil, fmt.Errorf("%q is unsupported", d.Type)
}

func readCsr(path string) (*x509.CertificateRequest, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", path)
	}

	if d.Type == "CERTIFICATE REQUEST" {
		return x509.ParseCertificateRequest(d.Bytes)
	}

	return nil, fmt.Errorf("%q is unsupported", d.Type)
}

func readCer(path string) ([]*x509.Certificate, error) {
	var cs []*x509.Certificate

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		d, r := pem.Decode(b)
		if d == nil {
			break
		}

		if d.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%q is unsupported", d.Type)
		}

		cert, err := x509.ParseCertificate(d.Bytes)
		if err != nil {
			return nil, err
		}

		cs = append(cs, cert)

		b = r
	}

	if len(cs) == 0 {
		return nil, errors.New("noCertificates")
	}

	return cs, nil
}

/* */

func account(q *cli.Context) error {
	key, err := readKey(q.String("a"))
	if err != nil {
		return err
	}

	/* */

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	p := acme.NewClient(key)

	if err := p.Describe(ctx, q.String("end-point")); err != nil {
		return err
	}

	fmt.Printf("TOS: %q\n", p.Directory.Meta["termsOfService"])

	/* */

	req := make(map[string]interface{})

	if q.IsSet("c") {
		req["contact"] = []string{"mailto:" + q.String("c")}
	}

	if q.IsSet("agree-tos") {
		req["termsOfServiceAgreed"] = q.Bool("agree-tos")
	}

	if _, err := p.NewAccount(ctx, req); err != nil {
		return err
	}

	/* */

	return nil
}

/* */

type scripter struct {
	Script string

	domains []string
}

func (p *scripter) DNSSetup(ctx context.Context, domain, text string) bool {
	log.Printf("> %s %s %s\n", p.Script, domain, text)
	cmd := exec.Command(p.Script, domain, text)
	if err := cmd.Run(); err != nil {
		log.Println(err)
		return false
	}
	p.domains = append(p.domains, domain)
	return true
}

func (p *scripter) Close() {
	for _, domain := range p.domains {
		log.Printf("> %s %s\n", p.Script, domain)
		cmd := exec.Command(p.Script, domain)
		if err := cmd.Run(); err != nil {
			log.Println(err)
		}
	}
}

type lego struct {
	Script string

	domains []struct{ domain, token, keyAuth string }
}

func (p *lego) DNSSetup(ctx context.Context, domain, text string) bool {
	log.Printf("dummy > %s %s %s\n", p.Script, domain, text)
	return false
}

func (p *lego) Present(ctx context.Context, domain, token, keyAuth string) error {
	log.Printf("> %s %s %s %s\n", p.Script, domain, token, keyAuth)
	cmd := exec.Command(p.Script, domain, token, keyAuth)
	if err := cmd.Run(); err != nil {
		return err
	}
	p.domains = append(p.domains, struct{ domain, token, keyAuth string }{domain, token, keyAuth})
	return nil
}

func (p *lego) Close() {
	for _, domain := range p.domains {
		log.Printf("> %s --cleanup %s %s %s\n", p.Script, domain.domain, domain.token, domain.keyAuth)
		cmd := exec.Command(p.Script, "--cleanup", domain.domain, domain.token, domain.keyAuth)
		if err := cmd.Run(); err != nil {
			log.Println(err)
		}
	}
}

/* */

func renew(q *cli.Context) error {
	key, err := readKey(q.String("a"))
	if err != nil {
		return err
	}

	var request *x509.CertificateRequest

	if q.IsSet("d") {
		pri, err := readKey(q.String("p"))
		if err != nil {
			return err
		}

		domain := q.String("d")

		request = &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: domain},
			DNSNames: []string{domain},
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, request, pri)
		if err != nil {
			return err
		}

		request.Raw = csr

	} else {
		request, err = readCsr(q.String("c"))
		if err != nil {
			return err
		}
	}

	if request == nil {
		return errors.New("noCertificateRequest")
	}

	/* */

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	p := acme.NewClient(key)

	if q.Bool("v") {
		p.Verbose = true
	}

	if err := p.Describe(ctx, q.String("end-point")); err != nil {
		return err
	}

	/* */

	r := acme.NewRenew(p)

	if q.IsSet("l") {
		l := &lego{Script: q.String("l")}
		r.Continue = l

		defer l.Close()

	} else if q.IsSet("s") {
		s := &scripter{Script: q.String("s")}
		r.Continue = s

		defer s.Close()
	}

	err = r.Order(ctx, request)
	if err != nil {
		return err
	}

	cert, err := r.GetCertificate(ctx)
	if err != nil {
		return err
	}

	/* */

	args := q.Args()
	if args.Present() {
		if err := ioutil.WriteFile(args.First(), cert, 0644); err != nil {
			return err
		}
	} else {
		if _, err := os.Stdout.Write(cert); err != nil {
			return err
		}
	}

	/* */

	return nil
}

/* */

func preview(q *cli.Context) error {
	cs, err := readCer(q.Args().First())
	if err != nil {
		return err
	}

	expired := false

	now := time.Now()
	exp := now.AddDate(0, 0, q.Int("d"))

	for _, cert := range cs {
		fmt.Printf("DNS: %q\n", cert.DNSNames)
		fmt.Printf("EXP: %q\n", cert.NotAfter)

		if exp.After(cert.NotAfter) {
			expired = true
		}
	}

	if expired {
		return errors.New("certificate will be expired")
	}

	return nil
}

/* */

func wrap(f func(*cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		err := f(ctx)
		if err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}
}

func main() {
	app := cli.NewApp()

	app.Name = "wild let's encrypt"
	app.Usage = "ACMEv2 client tool"

	app.Commands = append(app.Commands,
		cli.Command{
			Name:  "account",
			Usage: "register account",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "end-point",
					Value: EP,
				},
				cli.StringFlag{
					Name:  "account-key, a",
					Value: "account.key",
				},
				cli.StringFlag{
					Name: "contact, c",
				},
				cli.BoolFlag{
					Name: "agree-tos",
				},
			},
			Action: wrap(account),
		})

	app.Commands = append(app.Commands,
		cli.Command{
			Name:  "renew",
			Usage: "renew certificate",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "end-point",
					Value: EP,
				},
				cli.StringFlag{
					Name:  "account-key, a",
					Value: "account.key",
				},
				cli.StringFlag{
					Name:  "private-key, p",
					Value: "server.key",
				},
				cli.StringFlag{
					Name:  "csr, c",
					Value: "server.csr",
				},
				cli.StringFlag{
					Name: "domain, d",
				},
				cli.StringFlag{
					Name: "dns-script, s",
				},
				cli.StringFlag{
					Name: "dns-lego, l",
				},
				cli.BoolFlag{
					Name: "verbose, v",
				},
			},
			Action: wrap(renew),
		})

	app.Commands = append(app.Commands,
		cli.Command{
			Name:  "cert",
			Usage: "preview certificate",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "expire-days, d",
					Value: 30,
				},
			},
			Action: wrap(preview),
		})

	app.Run(os.Args)
}

/* */
