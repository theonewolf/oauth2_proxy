package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testAzureV2Provider(hostname string) *AzureV2Provider {
	p := NewAzureV2Provider(
		&ProviderData{
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             ""})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
		updateURL(p.Data().ProtectedResource, hostname)
	}
	return p
}

func TestAzureV2ProviderDefaults(t *testing.T) {
	p := testAzureV2Provider("")
	assert.NotEqual(t, nil, p)
	p.Configure("")
	assert.Equal(t, "AzureV2", p.Data().ProviderName)
	assert.Equal(t, "common", p.Tenant)
	assert.Equal(t, "https://login.microsoftonline.com/common/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://login.microsoftonline.com/common/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.windows.net",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func TestAzureV2ProviderOverrides(t *testing.T) {
	p := NewAzureV2Provider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			ProtectedResource: &url.URL{
				Scheme: "https",
				Host:   "example.com"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "AzureV2", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "https://example.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestAzureV2SetTenant(t *testing.T) {
	p := testAzureV2Provider("")
	p.Configure("example")
	assert.Equal(t, "AzureV2", p.Data().ProviderName)
	assert.Equal(t, "example", p.Tenant)
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.windows.net",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func testAzureV2Backend(payload string) *httptest.Server {
	path := "/me"
	query := "api-version=1.6"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if (r.URL.Path != path || r.URL.RawQuery != query) && r.Method != "POST" {
				w.WriteHeader(404)
			} else if r.Method == "POST" && r.Body != nil {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAzureV2ProviderGetEmailAddress(t *testing.T) {
	b := testAzureV2Backend(`{ "mail": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureV2ProviderGetEmailAddressMailNull(t *testing.T) {
	b := testAzureV2Backend(`{ "mail": null, "otherMails": ["user@windows.net", "altuser@windows.net"] }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureV2ProviderGetEmailAddressGetUserPrincipalName(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureV2ProviderGetEmailAddressFailToGetEmailAddress(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureV2ProviderGetEmailAddressEmptyUserPrincipalName(t *testing.T) {
	b := testAzureV2Backend(`{ "mail": null, "otherMails": [], "userPrincipalName": "" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", email)
}

func TestAzureV2ProviderGetEmailAddressIncorrectOtherMails(t *testing.T) {
	b := testAzureV2Backend(`{ "mail": null, "otherMails": "", "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureV2ProviderRedeemReturnsIdToken(t *testing.T) {
	b := testAzureV2Backend(`{ "id_token": "testtoken1234", "expires_on": "1136239445", "refresh_token": "refresh1234" }`)
	defer b.Close()
	timestamp, err := time.Parse(time.RFC3339, "2006-01-02T22:04:05Z")
	assert.Equal(t, nil, err)

	bURL, _ := url.Parse(b.URL)
	p := testAzureV2Provider(bURL.Host)
	p.Data().RedeemURL.Path = "/common/oauth2/token"
	s, err := p.Redeem("https://localhost", "1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, "testtoken1234", s.IDToken)
	assert.Equal(t, timestamp, s.ExpiresOn.UTC())
	assert.Equal(t, "refresh1234", s.RefreshToken)
}
