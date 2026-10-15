package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

const HeaderContextKey = "headers"

func getRequestObject(request_uri string, outerClientID string, ctx context.Context) (*presentation.RequestObject, error) {
	logger := common.GetEnvironment().GetLogger()
	requestUrl, err := parsePercentEncodedUrl(request_uri, true)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to parse uri %s", request_uri), err)
	}

	/*if url.Scheme != "https" {
		return nil, errors.New("Unsupported HTTP Scheme for presentation definition.")
	}*/

	presRequest, err := sendRequestWithRedirects(requestUrl, ctx)
	if err != nil {
		logger.Error(err, "error getting request object for url "+requestUrl.String())
		return nil, err
	}
	return presRequest, err
}

func parsePercentEncodedUrl(request_uri string, setHttpSchema bool) (*url.URL, error) {
	request_uri, err := url.PathUnescape(request_uri)

	if err != nil {
		return nil, err
	}
	requestUrl, err := url.Parse(request_uri)

	if err != nil {
		return nil, err
	}
	if setHttpSchema && requestUrl.Scheme == "" {
		requestUrl.Scheme = common.GetEnvironment().GetConfig().ExternalPresentation.ClientUrlSchema
	}
	validated, err := validateOutboundURL(requestUrl.String(), common.GetEnvironment().GetConfig(), true)
	if err != nil {
		return nil, err
	}
	return validated, nil
}

func sendRequestWithRedirects(url *url.URL, ctx context.Context) (*presentation.RequestObject, error) {
	client := externalHTTPClient(common.GetEnvironment().GetConfig())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, errors.Join(errors.New("could not create request"), err)
	}

	// Never forward incoming Authorization/Cookie headers to an external verifier.
	req.Header.Set("Accept", "application/jwt")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, errors.Join(errors.New("could not send request"), err)
	} else if resp.StatusCode >= http.StatusBadRequest {
		var errBody = "<null>"
		if body, er := io.ReadAll(io.LimitReader(resp.Body, 4096)); er == nil && len(body) > 0 {
			errBody = string(body)
		}
		err = fmt.Errorf("request url %s returned status %s with data %s", url.String(), resp.Status, errBody)
		return nil, err
	} else if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		return nil, fmt.Errorf("redirects are forbidden for request_uri (HTTP %d)", resp.StatusCode)
	}
	return handleSuccessfulResponse(resp, outerClientID)
}

func GetHttpClient() *http.Client { return secureHTTPClient() }

func handleSuccessfulResponse(resp *http.Response, outerClientID string) (*presentation.RequestObject, error) {
	var object = presentation.RequestObject{}
	cT, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || cT != "application/jwt" {
		return nil, fmt.Errorf("unsupported response Content-Type `%s`, expected `application/jwt`", resp.Header.Get("Content-Type"))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, errors.Join(errors.New("could not parse response body"), err)
	}
	if int64(len(body)) > maxHTTPResponseBytes {
		return nil, errors.New("request object exceeds size limit")
	}

	tokenString := strings.TrimSpace(string(body))

	//Potentially here should be checked what client_id_scheme is used. Assumption here: DID is used, DID is in the kid referenced.
	//In the future here must be check if something else than DID is used by opening the token before signature check, but spec is still too unstable for big evals

	claims, err := verifyExternalRequestJWT(resp.Request.Context(), tokenString, outerClientID)
	if err != nil {
		return nil, err
	}

	jsonTok, err := json.Marshal(claims)

	if err != nil {
		return nil, errors.Join(errors.New("error marshalling token json"), err)
	}

	err = json.Unmarshal(jsonTok, &object)

	if err != nil {
		return nil, errors.Join(errors.New("error unmarshalling token into presentation request"), err)
	}

	return &object, err
}
