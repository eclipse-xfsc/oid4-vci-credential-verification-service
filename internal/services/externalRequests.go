package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/jwt"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
)

const HeaderContextKey = "headers"

func getRequestObject(request_uri string, ctx context.Context) (*presentation.RequestObject, error) {
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
	if setHttpSchema {
		common.GetEnvironment().GetLogger().Logger.Info("setting http schema", "schema", common.GetEnvironment().GetConfig().ExternalPresentation.ClientUrlSchema, "url", requestUrl.String())
		requestUrl.Scheme = common.GetEnvironment().GetConfig().ExternalPresentation.ClientUrlSchema
	}
	return requestUrl, err
}

func sendRequestWithRedirects(url *url.URL, ctx context.Context) (*presentation.RequestObject, error) {
	client := GetHttpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, errors.Join(errors.New("could not create request"), err)
	}

	req.Header = ctx.Value(HeaderContextKey).(http.Header)
	resp, err := client.Do(req)

	if err != nil {
		return nil, errors.Join(errors.New("could not send request"), err)
	} else if resp.StatusCode >= http.StatusBadRequest {
		var errBody = "<null>"
		if body, er := io.ReadAll(resp.Body); er == nil && len(body) > 0 {
			errBody = string(body)
		}
		err = fmt.Errorf("request url %s returned status %s with data %s", url.String(), resp.Status, errBody)
		return nil, err
	} else if resp.StatusCode < http.StatusMultipleChoices {
		return handleSuccessfulResponse(resp)
	} else {
		return nil, fmt.Errorf("cannot support more than %v embedded redirects", 10)
	}
}

func GetHttpClient() *http.Client {
	// fixme this is a workaround for the self signed certificate
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Use the Transport in the client
	client := &http.Client{Transport: transport}
	return client
}

func handleSuccessfulResponse(resp *http.Response) (*presentation.RequestObject, error) {
	var object = presentation.RequestObject{}
	if cT := resp.Header.Get("Content-Type"); cT != "application/jwt" {
		return nil, fmt.Errorf("unsupported response Content-Type `%s`, expected `application/jwt`", cT)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Join(errors.New("could not parse response body"), err)
	}

	tokenString := strings.Replace(string(body), "\"", "", -1)

	//Potentially here should be checked what client_id_scheme is used. Assumption here: DID is used, DID is in the kid referenced.
	//In the future here must be check if something else than DID is used by opening the token before signature check, but spec is still too unstable for big evals

	token, err := jwt.Parse(tokenString)

	if err != nil {
		return nil, errors.Join(fmt.Errorf("error verifying token %s", tokenString), err)
	}

	jsonTok, err := json.Marshal(token)

	if err != nil {
		return nil, errors.Join(errors.New("error marshalling token json"), err)
	}

	err = json.Unmarshal(jsonTok, &object)

	if err != nil {
		return nil, errors.Join(errors.New("error unmarshalling token into presentation request"), err)
	}

	return &object, err
}
