package acme

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
)

type Continue interface {
	DNSSetup(ctx context.Context, domain, text string) bool
}

type Lego interface {
	Continue
	Present(ctx context.Context, domain, token, keyAuth string) error
}

type Renew struct {
	cli *Client

	Continue Continue

	ChaRetry int
	ChaLevel int
	FinRetry int
	DNSProbe int
	DNSRetry int
	DNSLevel int
	Wait     int

	request *x509.CertificateRequest

	Certificate string
}

func (p *Renew) DNSSetup(ctx context.Context, domain, text string) bool {
	fmt.Printf("DNSSetup TXT: %s %s\nContinue?", domain, text)

	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		if sc.Text() != "y" {
			return false
		}
	} else {
		if err := sc.Err(); err != nil {
			return false
		}
	}

	return true
}

/* */

func NewRenew(cli *Client) *Renew {
	p := &Renew{
		cli: cli,

		ChaRetry: 60,
		ChaLevel: 10,
		FinRetry: 20,
		DNSProbe: 60,
		DNSRetry: 60,
		DNSLevel: 10,
		Wait:     1500, // ms
	}

	p.Continue = p

	return p
}

func (p *Renew) Order(ctx context.Context, req *x509.CertificateRequest) error {
	p.request = req

	return p.doRenew(ctx, req.DNSNames)
}

func (p *Renew) GetCertificate(ctx context.Context) ([]byte, error) {
	return p.cli.GetCertificate(ctx, p.Certificate)
}

/* */

func (p *Renew) doRenew(ctx context.Context, domains []string) error {
	// Check account
	if _, err := p.cli.LookupAccount(ctx); err != nil {
		return err
	}

	// New order
	var ids []Identifier
	for _, domain := range domains {
		ids = append(ids, Identifier{Type: "dns", Value: domain})
	}
	req := map[string]interface{}{
		"identifiers": ids,
	}

	oid, order, err := p.cli.NewOrder(ctx, req)
	if err != nil {
		return err
	}

	if order.Status != "pending" {
		return errors.New("order.status")
	}

	if len(order.Authorizations) == 0 {
		return errors.New("order.authorizations")
	}

	// Authorize
	for _, aid := range order.Authorizations {
		if err := p.doAuthz(ctx, aid); err != nil {
			return err
		}
	}

	// Finalize
	if err := p.doFinalize(ctx, order, oid); err != nil {
		return err
	}

	return nil
}

func (p *Renew) doAuthz(ctx context.Context, aid string) error {
	authz, err := p.cli.GetAuthorization(ctx, aid)
	if err != nil {
		return err
	}

	if authz.Status == "valid" { // OK
		return nil
	}

	/* */

	if len(authz.Challenges) == 0 {
		return errors.New("authz.challenges")
	}

	var cha *Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			cha = &c
			break
		}
	}

	if cha == nil {
		return errors.New("challenges.dns-01")
	}

	if cha.Status == "valid" { // OK
		return nil
	}

	/* */

	if err := p.doChallenge(ctx, authz, cha); err != nil {
		return err
	}

	/* */

	if cha.Status == "pending" {
		ka, err := p.cli.GetKeyAuthorization(cha.Token)
		if err != nil {
			return err
		}

		req := map[string]interface{}{
			"keyAuthorization": ka,
		}

		if _, err = p.cli.PostChallenge(ctx, cha.URL, req); err != nil {
			return err
		}
	}

	/* */

	ms := 0
	for i := 0; i < p.ChaRetry; i++ {
		if i%p.ChaLevel == 0 {
			ms += p.Wait
		}
		Sleep(ctx, ms)

		authz, err := p.cli.GetAuthorization(ctx, aid)
		if err != nil {
			return err
		}

		if authz.Status == "valid" {
			return nil
		}
	}

	/* */

	return errors.New("challenge.timeout")
}

func (p *Renew) doChallenge(ctx context.Context, authz *Authorization, cha *Challenge) error {
	domain := "_acme-challenge." + authz.Identifier.Value
	text, err := p.cli.GetDNS01Challenge(cha.Token)
	if err != nil {
		return err
	}

	if lego, ok := p.Continue.(Lego); ok {
		keyAuth, err := p.cli.GetKeyAuthorization(cha.Token)
		if err != nil {
			return err
		}

		if err := lego.Present(ctx, authz.Identifier.Value, cha.Token, keyAuth); err != nil {
			return err
		}

	} else {
		if !p.Continue.DNSSetup(ctx, domain, text) {
			return errors.New("_acme-challenge.abort")
		}
	}

	/* */

	ms := 0
	for i := 0; i < p.DNSProbe+p.DNSRetry; i++ {
		if i%p.DNSLevel == 0 {
			ms += p.Wait
		}
		Sleep(ctx, ms)

		ts, err := net.LookupTXT(domain)
		if err != nil {
			if i < p.DNSProbe {
				continue
			}
			return err
		}

		for _, v := range ts {
			if v == text {
				return nil
			}
		}
	}

	/* */

	return errors.New("dns.timeout")
}

func (p *Renew) doFinalize(ctx context.Context, order *Order, oid string) error {
	req := map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(p.request.Raw),
	}

	if _, err := p.cli.PostFinalize(ctx, order.Finalize, req); err != nil {
		return err
	}

	/* */

	for i := 0; i < p.FinRetry; i++ {
		Sleep(ctx, p.Wait)

		order, err := p.cli.GetOrder(ctx, oid)
		if err != nil {
			return err
		}

		if order.Status == "valid" {
			p.Certificate = order.Certificate
			return nil
		}
	}

	/* */

	return errors.New("order.timeout")
}
