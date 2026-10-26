package common

import (
	"errors"
	"net/url"
	"strings"
)

// TenantOrigin validates the public origin supplied by the trusted tenant gateway.
// The gateway must overwrite X-Origin; never forward a client-controlled value.
func TenantOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return nil, errors.New("X-ORIGIN must be an HTTPS origin without path, query or fragment")
	}
	return u, nil
}

// ResolveTenantEndpoint resolves a configured wallet path against a trusted tenant origin.
// Absolute endpoints remain supported for backwards compatibility.
func ResolveTenantEndpoint(origin, endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("authorize endpoint is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		return endpoint, nil
	}
	if !strings.HasPrefix(endpoint, "/") || strings.HasPrefix(endpoint, "//") || u.Host != "" || u.Fragment != "" {
		return "", errors.New("authorize endpoint must be an absolute URL or an absolute path")
	}
	base, err := TenantOrigin(origin)
	if err != nil {
		return "", err
	}
	base.Path = u.Path
	base.RawQuery = u.RawQuery
	return base.String(), nil
}
