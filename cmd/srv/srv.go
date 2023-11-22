package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ale8k/authcode-flow-go-poc/internal/jujumsgs"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/gorilla/websocket"

	ory "github.com/ory/client-go"
	"github.com/ory/x/randx"
	"golang.org/x/oauth2"
)

type jimmLoginRequest struct {
	LoginType  string `json:"login-type"`
	LoginState string `json:"login-state"` // 1 of: 'request-auth-code-url', 'exchange-auth-code'
	AuthCode   string `json:"auth-code,omitempty"`
}

const (
	RequestAuthCodeUrl = "request-auth-code-url"
	ExchangeAuthCode   = "exchange-auth-code"
)

// Simple struct to hold hydra oauth2 client
type oauthClientConfig struct {
	ClientId     string
	ClientSecret string
	CallbackUrl  string
}

type Server struct {
	oauthClientConfig oauthClientConfig
	oauthConfig       *oauth2.Config

	oidcProviderURL string
	wellKnownConfig WellKnownConfiguration

	httpClient *ServerHTTPClient

	upgrader websocket.Upgrader
	server   *http.Server

	jwtSecretSigningKey string
}

func NewServer(ctx context.Context, oidcProviderURL string) *Server {
	mux := http.NewServeMux()

	s := Server{
		oidcProviderURL: oidcProviderURL,
		httpClient:      NewServerHTTPClient(120),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		server: &http.Server{
			Addr:    ":8080",
			Handler: mux,
		},
		jwtSecretSigningKey: "diglett",
	}

	if err := s.setupHydra(ctx); err != nil {
		fmt.Println("failed to setup hydra: ", err)
		os.Exit(1)
	}
	if err := s.setupWellknownConfig(); err != nil {
		fmt.Println("failed to setup wellknown config: ", err)
		os.Exit(1)
	}
	s.setupOauthClient(ctx)

	mux.HandleFunc("/ws", s.handleWS)

	return &s
}

func (s *Server) Start() {
	log.Println("Server started on :8080")
	err := s.server.ListenAndServe()
	if err != nil {
		log.Fatal("Server error:", err)
	}
}

// setupHydra creates an oauth2-client within hydra capable of auth code flow + PKCE.
// This is purely for demonstration purposes and automating the PoC.
func (s *Server) setupHydra(ctx context.Context) error {
	oAuth2Client := *ory.NewOAuth2Client()

	// Setup private ory client
	privateConfiguration := ory.NewConfiguration()
	privateConfiguration.Servers = []ory.ServerConfiguration{
		{
			URL: "http://127.0.0.1:4445", // Replace with your Hydra URL
		},
	}
	privateOryClient := ory.NewAPIClient(privateConfiguration)

	// Create the oauth2 client
	oAuth2Client.SetClientName("jaas")
	oAuth2Client.SetRedirectUris([]string{"http://127.0.0.1:5556/cb"})
	oAuth2Client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	oAuth2Client.SetResponseTypes([]string{"code", "id_token"})
	oAuth2Client.SetScope("openid offline email")
	oAuth2Client.SetTokenEndpointAuthMethod("client_secret_post") // For PKCE, must be post, for normal auth code, it is basic
	oAuth2Client.SetRequestObjectSigningAlg("RS256")

	jaasOauthClient, _, err := privateOryClient.OAuth2API.CreateOAuth2Client(ctx).OAuth2Client(oAuth2Client).Execute()
	if err != nil {
		return err
	}
	s.oauthClientConfig = oauthClientConfig{
		ClientId:     jaasOauthClient.GetClientId(),
		ClientSecret: jaasOauthClient.GetClientSecret(),
		CallbackUrl:  jaasOauthClient.GetRedirectUris()[0],
	}

	return nil
}

// setupWellknownConfig retrieves the openid config for our provider and stores it on the server
// for later use.
func (s *Server) setupWellknownConfig() error {
	c := WellKnownConfiguration{}

	res, err := s.httpClient.Get(s.oidcProviderURL + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	s.wellKnownConfig = c
	return nil
}

// setupOauthClient sets up an oauthClient and stores it on the server for later use.
func (s *Server) setupOauthClient(ctx context.Context) {
	clientOAuthConfig := oauth2.Config{
		ClientID:     s.oauthClientConfig.ClientId,
		ClientSecret: s.oauthClientConfig.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: s.wellKnownConfig.TokenEndpoint,
			AuthURL:  s.wellKnownConfig.AuthorizationEndpoint, // Because we're providing the auth url to the client here, we need this
		},
		Scopes:      []string{"openid", "offline", "email"}, // Because we're providing the auth url to the client here, we need this
		RedirectURL: s.oauthClientConfig.CallbackUrl,        // fails if doesnt match hydra redirect-url :)
	}
	s.oauthConfig = &clientOAuthConfig
}

// ExchangeAuthCode exchanges an auth code for the desired response types, i.e., code, id token etc.
func (s *Server) ExchangeAuthCode(ctx context.Context, authCode string, codeVerifier string) (*oauth2.Token, error) {
	return s.oauthConfig.Exchange(ctx, authCode, oauth2.VerifierOption(codeVerifier))
}

// GenerateAuthCodeURL
func (s *Server) GenerateAuthCodeURL() (string, string, string) {
	codeVerifier := oauth2.GenerateVerifier()
	codeChallenge := oauth2.S256ChallengeOption(codeVerifier)

	genState, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		fmt.Printf("Could not generate random state: %s", err)
		os.Exit(1)
	}

	state := string(genState)

	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		fmt.Printf("Could not generate random nonce: %s", err)
		os.Exit(1)
	}

	maxAge := 0

	authCodeURL := s.oauthConfig.AuthCodeURL(
		state,
		codeChallenge, // Enable PKCE
		oauth2.SetAuthURLParam("audience", strings.Join([]string{""}, "+")),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", strings.Join([]string{""}, "+")),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(maxAge)),
	)
	return authCodeURL, state, codeVerifier
}

// Login req/res 1 (auth code url)
// Login req/res 2 (send auth code to jimm)
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()
	for {
		fmt.Println("Incoming request")
		m := jujumsgs.Message{}
		if err := conn.ReadJSON(&m); err != nil {
			fmt.Println("error reading message: ", err)
			break
		} else {
			switch m.Request {
			case "Login":
				/*
					Simulate login facade
				*/
				p := jimmLoginRequest{}
				b, _ := m.Params.MarshalJSON()
				if err := json.Unmarshal(b, &p); err != nil {
					fmt.Println("error unmarshalling to jimm login request: ", err)
					break
				}

				if p.LoginState == RequestAuthCodeUrl {

					// Give client URL to click in login req resp
					url, _, _ := s.GenerateAuthCodeURL()
					respMap := map[string]string{
						"auth-code-url": url,
					}
					b, _ = json.Marshal(respMap)
					if err := conn.WriteJSON(jujumsgs.Message{
						RequestID: 69,
						Response:  b,
					}); err != nil {
						log.Println("Failed to write json: ", err)
						return
					}
				}

				if p.LoginState == ExchangeAuthCode {
					fmt.Println("AUTH CODE BOYZ: ", p.AuthCode)
				}
			}

		}
	}
}

func (s *Server) mintJWT() []byte {
	token, _ := jwt.NewBuilder().
		Audience([]string{"machine id here for the cli? idk"}).
		Subject("openid token sub?").
		Issuer("server host").
		JwtID("some hash").
		Expiration(time.Now().Add(time.Hour)). // is an hour ok?
		Build()

	freshToken, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256, s.jwtSecretSigningKey))
	return freshToken
}

func (s *Server) parseJWT(token []byte) jwt.Token {
	parsedToken, _ := jwt.Parse(token, jwt.WithKey(jwa.HS256, s.jwtSecretSigningKey))
	return parsedToken
}

func main() {
	ctx := context.Background()
	s := NewServer(ctx, "http://127.0.0.1:4444")
	s.Start()
}
