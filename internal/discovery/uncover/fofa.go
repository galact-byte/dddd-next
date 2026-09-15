package uncover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/uncover/sources"
)

const defaultFofaServer = "https://fofa.info"
const maxFofaResponse = 4 << 20

type fofaAgent struct{ server string }

func (a *fofaAgent) Name() string { return "fofa" }

func (a *fofaAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	endpoint, err := fofaEndpoint(a.server)
	if err != nil {
		return nil, err
	}
	if session.Keys.FofaEmail == "" || session.Keys.FofaKey == "" {
		return nil, errors.New("FOFA_EMAIL and FOFA_KEY are required")
	}
	results := make(chan sources.Result)
	go func() {
		defer close(results)
		if err := a.search(ctx, session, query, endpoint, results); err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: "fofa", Error: err})
		}
	}()
	return results, nil
}

func fofaEndpoint(server string) (*url.URL, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		server = defaultFofaServer
	}
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(server, "#") {
		return nil, errors.New("FOFA_SERVER must be an HTTP(S) base URL without credentials, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("FOFA_SERVER has an invalid port")
		}
	}
	return u.JoinPath("api/v1/search/all"), nil
}

func (a *fofaAgent) search(ctx context.Context, shared *sources.Session, query *sources.Query, endpoint *url.URL, results chan sources.Result) error {
	// Only FOFA uses this transport. Recon APIs carry credentials, unlike scan
	// targets; do not inherit uncover's InsecureSkipVerify or cross-origin redirects.
	session := *shared
	httpClient := *shared.Client.HTTPClient
	transport := shared.Client.HTTPClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = false
	httpClient.Transport = transport
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !strings.EqualFold(req.URL.Host, endpoint.Host) || req.URL.Scheme != endpoint.Scheme {
			return http.ErrUseLastResponse
		}
		return nil
	}
	client := retryablehttp.NewClient(retryablehttp.Options{
		HttpClient: &httpClient, Timeout: httpClient.Timeout,
		RetryMax: shared.RetryMax, RetryWaitMin: time.Second, RetryWaitMax: 2 * time.Second,
	})
	client.HTTPClient2 = &httpClient
	client.ErrorHandler = retryablehttp.PassthroughErrorHandler
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			var certErr *tls.CertificateVerificationError
			var authorityErr x509.UnknownAuthorityError
			var netErr net.Error
			if errors.As(err, &certErr) || errors.As(err, &authorityErr) || (errors.As(err, &netErr) && netErr.Timeout()) {
				return false, err
			}
			return shared.Client.CheckRetry(ctx, resp, err)
		}
		return resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500), nil
	}
	session.Client = client
	defer transport.CloseIdleConnections()

	pageSize := min(100, query.Limit)
	seen := 0
	for page := 1; seen < query.Limit; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		requestURL := *endpoint
		requestURL.RawQuery = url.Values{
			"key": {session.Keys.FofaKey}, "email": {session.Keys.FofaEmail},
			"qbase64": {base64.StdEncoding.EncodeToString([]byte(query.Query))},
			"fields":  {"ip,port,host"}, "page": {strconv.Itoa(page)},
			"size": {strconv.Itoa(pageSize)}, "full": {"false"},
		}.Encode()
		body, err := fofaPage(ctx, &session, requestURL.String())
		if err != nil {
			return err
		}
		if body.Error {
			return fmt.Errorf("API error: %s", reconMessage(body.ErrMsg, session.Keys))
		}
		invalid := 0
		for _, row := range body.Results {
			if seen >= query.Limit {
				break
			}
			seen++
			result, err := fofaResult(row)
			if err != nil {
				invalid++
				continue
			}
			if !sources.SendResult(ctx, results, result) {
				return ctx.Err()
			}
		}
		if invalid > 0 {
			sources.SendResult(ctx, results, sources.Result{Source: "fofa", Error: fmt.Errorf("page %d: skipped %d invalid result rows", page, invalid)})
		}
		if len(body.Results) == 0 || seen >= body.Size {
			break
		}
	}
	return nil
}

type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`
	Results [][]string `json:"results"`
}

func fofaPage(ctx context.Context, session *sources.Session, address string) (*fofaResponse, error) {
	req, err := sources.NewHTTPRequest(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("cannot construct FOFA request")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := session.Do(req, "fofa")
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if resp != nil {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, errors.New("request timed out")
		}
		// The dependency includes the full request URL (and key) in its errors.
		return nil, errors.New("request failed; check FOFA_SERVER, network, proxy and TLS certificate")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFofaResponse+1))
	if err != nil {
		return nil, errors.New("could not read API response")
	}
	if len(data) > maxFofaResponse {
		return nil, errors.New("API response exceeds 4 MiB")
	}
	var wire struct {
		Error   *bool      `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Size    *int       `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, errors.New("invalid FOFA JSON response")
	}
	if wire.Error == nil || (!*wire.Error && (wire.Size == nil || *wire.Size < 0 || wire.Results == nil)) {
		return nil, errors.New("invalid FOFA response: expected error, size and results fields")
	}
	body := &fofaResponse{Error: *wire.Error, ErrMsg: wire.ErrMsg, Results: wire.Results}
	if wire.Size != nil {
		body.Size = *wire.Size
	}
	return body, nil
}

func reconMessage(message string, keys *sources.Keys) string {
	for _, secret := range []string{keys.FofaKey, keys.FofaEmail, keys.HunterToken, keys.QuakeToken} {
		if secret == "" {
			continue
		}
		for _, value := range []string{url.QueryEscape(secret), url.PathEscape(secret), secret} {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	message = strings.Join(strings.Fields(message), " ")
	if runes := []rune(message); len(runes) > 300 {
		message = string(runes[:300]) + "..."
	}
	if message == "" {
		return "unspecified error"
	}
	return message
}

func fofaResult(row []string) (sources.Result, error) {
	if len(row) != 3 {
		return sources.Result{}, errors.New("invalid columns")
	}
	ip, err := netip.ParseAddr(row[0])
	if err != nil {
		return sources.Result{}, err
	}
	port, err := strconv.Atoi(row[1])
	if err != nil || port < 1 || port > 65535 {
		return sources.Result{}, errors.New("invalid port")
	}
	result := sources.Result{Source: "fofa", IP: ip.String(), Port: port, Host: ip.String()}
	host := strings.TrimSpace(row[2])
	if host == "" {
		return result, nil
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
			return sources.Result{}, errors.New("invalid host URL")
		}
		result.Host, result.Url = u.Hostname(), u.String()
	} else if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		result.Host = addr.String()
	} else {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if strings.ContainsAny(host, ":/?#@\\ \t\r\n") {
			return sources.Result{}, errors.New("invalid host")
		}
		result.Host = host
	}
	return result, nil
}
