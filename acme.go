package acme

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

/* */

type Directory struct {
	NewAccount string
	NewNonce   string
	RevokeCert string
	NewOrder   string
	KeyChange  string

	Meta map[string]string
}

type Account struct {
	Status  string
	Contact []string
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	Status         string
	Expires        string
	Identifiers    []Identifier
	Authorizations []string
	Finalize       string
	Certificate    string
}

type Authorization struct {
	Status     string
	Expires    string
	Identifier Identifier
	Challenges []Challenge
}

type Challenge struct {
	Type             string
	URL              string
	Status           string
	Validated        string
	Token            string
	KeyAuthorization string
}

/* */

type Error struct {
	Status int
	Type   string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Status, e.Type, e.Detail)
}

func ErrorWithResponse(res *http.Response) error {
	b, _ := ioutil.ReadAll(res.Body)
	e := &Error{Status: res.StatusCode}
	if err := json.Unmarshal(b, e); err != nil {
		e.Detail = string(b)
		if e.Detail == "" {
			e.Detail = res.Status
		}
	}
	return e
}

/* */

type Client struct {
	Logger  *log.Logger
	Verbose bool

	HTTPClient *http.Client

	Key crypto.Signer
	Kid string

	Directory *Directory

	newNonce   string
	newAccount string
	newOrder   string

	nonMux sync.Mutex
	nonSet map[string]struct{}
}

func NewClient(key crypto.Signer) *Client {
	cli := &Client{Key: key}

	cli.Logger = log.New(os.Stderr, "", 0)

	cli.HTTPClient = http.DefaultClient

	return cli
}

func (p *Client) getJson(res *http.Response, q interface{}) error {
	by, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if p.Verbose {
		p.Logger.Printf("[RES ] : %s", string(by))
	}

	if len(by) == 0 {
		return nil
	}

	if err := json.Unmarshal(by, q); err != nil {
		return err
	}

	return nil
}

func (p *Client) Describe(ctx context.Context, url string) error {
	res, err := p.DoGet(ctx, url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return ErrorWithResponse(res)
	}

	q := &Directory{}
	if err := p.getJson(res, q); err != nil {
		return err
	}

	p.Directory = q

	p.newNonce = q.NewNonce
	p.newAccount = q.NewAccount
	p.newOrder = q.NewOrder

	return nil
}

func (p *Client) GetNonce(ctx context.Context, url string) (string, error) {
	p.nonMux.Lock()
	defer p.nonMux.Unlock()

	var nonce string

	if len(p.nonSet) > 0 {
		for nonce = range p.nonSet {
			delete(p.nonSet, nonce)
			break
		}
		return nonce, nil
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nonce, err
	}

	res, err := p.do(ctx, req)
	if err != nil {
		return nonce, err
	}

	nonce = res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return nonce, errors.New("GetNonce")
	}

	return nonce, nil
}

func (p *Client) PutNonce(nonce string) {
	p.nonMux.Lock()
	defer p.nonMux.Unlock()

	if p.nonSet == nil {
		p.nonSet = make(map[string]struct{})
	}
	p.nonSet[nonce] = struct{}{}
}

func (p *Client) addNonce(res *http.Response) {
	nonce := res.Header.Get("Replay-Nonce")
	if nonce != "" {
		p.PutNonce(nonce)
	}
}

func (p *Client) flushNonce() {
	p.nonMux.Lock()
	defer p.nonMux.Unlock()

	p.nonSet = nil
}

func (p *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	res, err := p.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (p *Client) DoGet(ctx context.Context, url string) (*http.Response, error) {
	if p.Verbose {
		p.Logger.Printf("[GET ] : %s", url)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res, err := p.do(ctx, req)
	if err != nil {
		return nil, err
	}

	p.addNonce(res)

	return res, nil
}

func (p *Client) DoPost(ctx context.Context, url, ctype string, body io.Reader) (*http.Response, error) {
	if p.Verbose {
		p.Logger.Printf("[POST] : %s", url)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", ctype)

	res, err := p.do(ctx, req)
	if err != nil {
		return nil, err
	}

	p.addNonce(res)

	return res, nil
}

func (p *Client) PostJWS(ctx context.Context, url string, body interface{}) (*http.Response, error) {
	nonce, err := p.GetNonce(ctx, p.newNonce)
	if err != nil {
		return nil, err
	}

	b, err := EncodeJWS(body, p.Key, nonce, p.Kid, url)
	if err != nil {
		return nil, err
	}

	res, err := p.DoPost(ctx, url, "application/jose+json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	return res, nil
}

func Sleep(ctx context.Context, ms int) error {
	wakeup := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer wakeup.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wakeup.C:
		return nil
	}
}

func (p *Client) PostJWSWithRetry(ctx context.Context, url string, body interface{}) (*http.Response, error) {
	for i := 0; i < 3; i++ {
		if i > 0 {
			err := Sleep(ctx, 3*1000)
			if err != nil {
				return nil, err
			}
		}

		res, err := p.PostJWS(ctx, url, body)
		if err != nil {
			return nil, err
		}

		if res.StatusCode >= 400 && res.StatusCode <= 599 {
			err := ErrorWithResponse(res)
			res.Body.Close()

			if e, ok := err.(*Error); ok && strings.HasSuffix(strings.ToLower(e.Type), ":badnonce") {
				p.flushNonce()

				continue
			}

			return nil, err
		}

		return res, nil
	}

	return nil, errors.New("Retry")
}

/* */

func linkHeader(h http.Header, rel string) []string {
	var links []string
	for _, v := range h["Link"] {
		parts := strings.Split(v, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "rel=") {
				continue
			}
			if v := strings.Trim(p[4:], `"`); v == rel {
				links = append(links, strings.Trim(parts[0], "<>"))
			}
		}
	}
	return links
}

func locationHeader(res *http.Response) (string, error) {
	location := res.Header.Get("Location")
	if location == "" {
		return "", errors.New("Location")
	}

	return location, nil
}

/* */

func (p *Client) getAccount(res *http.Response) (*Account, error) {
	q := &Account{}
	if err := p.getJson(res, q); err != nil {
		return nil, err
	}

	return q, nil
}

func (p *Client) NewAccount(ctx context.Context, req map[string]interface{}) (*Account, error) {
	res, err := p.PostJWSWithRetry(ctx, p.newAccount, req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	location, err := locationHeader(res)
	if err != nil {
		return nil, err
	}

	if p.Verbose {
		p.Logger.Printf("KID: %s", location)
	}

	p.Kid = location

	return p.getAccount(res)
}

func (p *Client) LookupAccount(ctx context.Context) (*Account, error) {
	req := map[string]interface{}{
		"onlyReturnExisting": true,
	}

	return p.NewAccount(ctx, req)
}

/* */

func (p *Client) getOrder(res *http.Response) (*Order, error) {
	q := &Order{}
	if err := p.getJson(res, q); err != nil {
		return nil, err
	}

	return q, nil
}

func (p *Client) NewOrder(ctx context.Context, req map[string]interface{}) (string, *Order, error) {
	res, err := p.PostJWSWithRetry(ctx, p.newOrder, req)
	if err != nil {
		return "", nil, err
	}

	defer res.Body.Close()

	location, err := locationHeader(res)
	if err != nil {
		return "", nil, err
	}

	order, err := p.getOrder(res)
	if err != nil {
		return "", nil, err
	}

	return location, order, nil
}

func (p *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	res, err := p.DoGet(ctx, url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	return p.getOrder(res)
}

/* */

func (p *Client) getAuthorization(res *http.Response) (*Authorization, error) {
	q := &Authorization{}
	if err := p.getJson(res, q); err != nil {
		return nil, err
	}

	return q, nil
}

func (p *Client) GetAuthorization(ctx context.Context, url string) (*Authorization, error) {
	res, err := p.DoGet(ctx, url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	return p.getAuthorization(res)
}

func (p *Client) PostAuthorization(ctx context.Context, url string, req map[string]interface{}) (*Authorization, error) {
	res, err := p.PostJWSWithRetry(ctx, url, req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	return p.getAuthorization(res)
}

/* */

func (p *Client) PostChallenge(ctx context.Context, url string, req map[string]interface{}) (*Challenge, error) {
	res, err := p.PostJWSWithRetry(ctx, url, req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	q := &Challenge{}
	if err := p.getJson(res, q); err != nil {
		return nil, err
	}

	return q, nil
}

func (p *Client) PostFinalize(ctx context.Context, url string, req map[string]interface{}) (*Order, error) {
	res, err := p.PostJWSWithRetry(ctx, url, req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	q := &Order{}
	if err := p.getJson(res, q); err != nil {
		return nil, err
	}

	return q, nil
}

/* */

func (p *Client) GetKeyAuthorization(token string) (string, error) {
	return KeyAuthorization(p.Key.Public(), token)
}

func (p *Client) GetDNS01Challenge(token string) (string, error) {
	return DNS01Challenge(p.Key.Public(), token)
}

/* */

func (p *Client) GetCertificate(ctx context.Context, url string) ([]byte, error) {
	res, err := p.DoGet(ctx, url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, ErrorWithResponse(res)
	}

	return ioutil.ReadAll(res.Body)
}

/* */
