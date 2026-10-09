package report

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/ht4w5/bd2geo/internal/info"
	"github.com/ht4w5/bd2geo/internal/model"
	"github.com/ht4w5/bd2geo/pkg/logx"
)

type FetcherConfig struct {
	CaFile   string
	CertFile string
	KeyFile  string
	URL      string
}

type Fetcher struct {
	cfg        FetcherConfig
	httpClient *http.Client
}

func NewFetcher(cfg FetcherConfig) (*Fetcher, error) {
	c, err := newMTLSClient(cfg.CaFile, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("create mtls client: %w", err)
	}

	return &Fetcher{
		cfg:        cfg,
		httpClient: c,
	}, nil
}

func (fs *Fetcher) Fetch(ctx context.Context) (*model.Report, error) {
	logger := logx.FromContext(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fs.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", info.String())
	logx.LogHTTPRequest(logger, req)

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	logx.LogHTTPResponse(logger, resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http response: %d", resp.StatusCode)
	}

	report, err := Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}

	return report, nil
}

func newMTLSClient(caFile, certFile, keyFile string) (*http.Client, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("client cert and key must be provided together: cert=%q key=%q", certFile, keyFile)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("bad CA pem: %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert %q/%q: %w", certFile, keyFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = tlsCfg

	return &http.Client{Transport: transport}, nil
}
