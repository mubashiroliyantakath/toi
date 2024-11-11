// Description: Plugin to check the token against the introspection endpoint.
package toi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/patrickmn/go-cache"
)

// Config the plugin configuration.
type Config struct {
	ClientId      string `json:"clientid,omitempty"`
	ClientSecret  string `json:"clientsecret,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// WellKnown struct to hold the introspection endpoint.
type WellKnown struct {
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
}

// IntrospectionResponse struct to hold the response from the introspection endpoint.
type IntrospectionResponse struct {
	Active    bool   `json:"active,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Username  string `json:"username,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ClientId:      "",
		ClientSecret:  "",
		Issuer:        "",
		TokenTypeHint: "",
	}
}

// ToiPlugin a plugin that checks the token against the introspection endpoint.
type ToiPlugin struct {
	next          http.Handler
	clientid      string
	clientsecret  string
	issuer        string
	tokenTypeHint string
	name          string
	cache         *cache.Cache
	template      *template.Template
}

// Create a new Toi Plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if config.ClientId == "" || config.ClientSecret == "" || config.Issuer == "" {
		return nil, fmt.Errorf("please set client id, client secret, and issuer for the introspection")
	}

	return &ToiPlugin{

		clientid:      config.ClientId,
		clientsecret:  config.ClientSecret,
		issuer:        config.Issuer,
		tokenTypeHint: config.TokenTypeHint,
		next:          next,
		name:          name,
		template:      template.New("demo").Delims("[[", "]]"),
		cache:         cache.New(5*time.Minute, 10*time.Minute),
	}, nil
}

func (a *ToiPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token := req.Header.Get("Authorization")
	if token == "" {
		http.Error(rw, "Authorization header is required", http.StatusUnauthorized)
		return
	}
	token = strings.Replace(token, "Bearer ", "", 1)
	if cachedResponse, found := a.cache.Get(token); found {
		if cachedResponse.(IntrospectionResponse).Active {
			os.Stdout.WriteString("Token is active in cache\n")
			a.next.ServeHTTP(rw, req)
			return
		}
	}
	c := http.Client{Timeout: time.Duration(5) * time.Second}
	openIdConfigEndpoint := fmt.Sprintf("%s/.well-known/openid-configuration", a.issuer)
	resp, err := c.Get(openIdConfigEndpoint)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, fmt.Sprintf("OpenID Config endpoint returned %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}
	introspectionEndpont := WellKnown{}
	err = json.NewDecoder(resp.Body).Decode(&introspectionEndpont)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	os.Stdout.WriteString(fmt.Sprintf("introspection endpoint: %s\n", introspectionEndpont.IntrospectionEndpoint))

	reqBody := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", token, a.clientid, a.clientsecret)
	if a.tokenTypeHint != "" {
		reqBody = fmt.Sprintf("%s&token_type_hint=%s", reqBody, a.tokenTypeHint)
	}
	req, err = http.NewRequest(http.MethodPost, introspectionEndpont.IntrospectionEndpoint, bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	respIntro, err := c.Do(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	switch respIntro.StatusCode {
	case http.StatusOK:
		break
	case http.StatusUnauthorized:
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	case http.StatusForbidden:
		http.Error(rw, "Forbidden", http.StatusForbidden)
	default:
		http.Error(rw, fmt.Sprintf("Introspection endpoint returned %d", respIntro.StatusCode), http.StatusInternalServerError)
		return
	}
	introspectionResponse := IntrospectionResponse{}
	err = json.NewDecoder(respIntro.Body).Decode(&introspectionResponse)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if !introspectionResponse.Active {
		http.Error(rw, "Token is not active", http.StatusUnauthorized)
		return
	}

	os.Stdout.WriteString("Token is active\n")
	a.cache.Set(token, introspectionResponse, time.Duration(int64(introspectionResponse.Exp)-time.Now().Unix())*time.Second)

	// defer resp.Body.Close()
	// defer respIntro.Body.Close()
	a.next.ServeHTTP(rw, req)
}
