// Package passwordcredentials implements the OAuth2.0 "password credentials" token flow.
// See https://tools.ietf.org/html/rfc6749#section-4.3
package passwordcredentials

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
)

// tokenFromInternal maps an *internal.Token struct into
// an *oauth2.Token struct.
func tokenFromInternal(t *internal.Token) *oauth2.Token {
	if t == nil {
		return nil
	}
	tk := &oauth2.Token{
		AccessToken:  t.AccessToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}
	return tk.WithExtra(t.Raw)
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.Token.
// This token is then mapped from *internal.Token into an *oauth2.Token which is returned along with an error.
func retrieveToken(ctx context.Context, c *Config, v url.Values) (*oauth2.Token, error) {
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
	if err != nil {
		return nil, err
	}
	return tokenFromInternal(tk), nil
}

// Config describes a Resource Owner Password Credentials OAuth2 flow, with the
// client application information, resource owner credentials and the server's
// endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// Resource owner username
	Username string

	// Resource owner password
	Password string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint oauth2.Endpoint

	// Scope specifies optional requested permissions.
	Scopes []string
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary. The underlying
// HTTP transport will be obtained using the provided context.
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// Token refreshes the token by using a new password credentials request.
// tokens received this way do not include a refresh token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	return retrieveToken(c.ctx, c.conf, url.Values{
		"grant_type": {"password"},
		"username":   {c.conf.Username},
		"password":   {c.conf.Password},
		"scope":      internal.CondVal(strings.Join(c.conf.Scopes, " ")),
	})
}
