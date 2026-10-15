package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
)

const maxHTTPResponseBytes int64 = 2 << 20

func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateOutboundURL(raw string, cfg *model.Config, external bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("URL host is required")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("URL scheme %q is forbidden", scheme)
	}
	if external && scheme != "https" && !cfg.IsDev {
		return nil, fmt.Errorf("URL scheme %q is forbidden for external endpoints; HTTPS is required outside dev mode", scheme)
	}
	if external && !cfg.IsDev {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
			return nil, fmt.Errorf("external URL points to a non-public address")
		}
	}
	return u, nil
}

// externalHTTPClient rejects non-public DNS resolutions in production, including
// DNS rebinding between URL validation and TCP connection establishment.
func externalHTTPClient(cfg *model.Config) *http.Client {
	client := secureHTTPClient()
	if cfg.IsDev {
		return client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, resolved := range addresses {
			ip := resolved.IP
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, errors.New("external endpoint has no public IP address")
	}
	transport.Proxy = nil
	client.Transport = transport
	return client
}
