package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	ory "github.com/ory/client-go"
	"github.com/ory/x/randx"
	"golang.org/x/oauth2"
)

/*
A simple go project demonstrating an oauth resource owner (in the form of CLI programatically)
communicating via auth code + PKCE flow to a client backed by ory hydra oauth provider/server.
*/

// Simple struct to hold hydra oauth2 client
type oauthClient struct {
	ClientId     string
	ClientSecret string
	CallbackUrl  string
}

// Hydra url + oauth endpoints
var oauthServerUrl = "http://127.0.0.1:4444"
var authoriseEndpoint = oauthServerUrl + "/oauth2/auth"
var tokenEndpoint = oauthServerUrl + "/oauth2/token"

// Generate PKCE code verifier and code challenge
var codeVerifier = oauth2.GenerateVerifier()
var codeChallenge = oauth2.S256ChallengeOption(codeVerifier)

// setupHydra creates an oauth2-client within hydra capable of auth code flow + PKCE.
func setupHydra(ctx context.Context) oauthClient {
	oAuth2Client := *ory.NewOAuth2Client()
	oAuth2Client.SetClientName("jaas")
	oAuth2Client.SetRedirectUris([]string{"http://127.0.0.1:5556/cb"})
	oAuth2Client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	oAuth2Client.SetResponseTypes([]string{"code", "id_token"})
	oAuth2Client.SetScope("openid offline email")
	oAuth2Client.SetTokenEndpointAuthMethod("client_secret_post") // For PKCE, must be post, for normal auth code, it is basic
	oAuth2Client.SetRequestObjectSigningAlg("RS256")

	privateConfiguration := ory.NewConfiguration()
	privateConfiguration.Servers = []ory.ServerConfiguration{
		{
			URL: "http://127.0.0.1:4445", // Replace with your Hydra URL
		},
	}
	privateOryClient := ory.NewAPIClient(privateConfiguration)
	jaasOauthClient, _, err := privateOryClient.OAuth2API.CreateOAuth2Client(ctx).OAuth2Client(oAuth2Client).Execute()
	if err != nil {
		fmt.Println("failed to create hydra client", err)
		os.Exit(1)
	}
	return oauthClient{
		ClientId:     jaasOauthClient.GetClientId(),
		ClientSecret: jaasOauthClient.GetClientSecret(),
		CallbackUrl:  jaasOauthClient.GetRedirectUris()[0],
	}
}

// cli represents any cli generating an auth code, as such, it only
// requires to know about the auth endpoint, client id, redirect url and scopes.
func cli(ctx context.Context, oauthClient oauthClient) string {
	cliOAuthConfig := oauth2.Config{
		ClientID: oauthClient.ClientId,
		Endpoint: oauth2.Endpoint{
			AuthURL: authoriseEndpoint,
		},
		RedirectURL: oauthClient.CallbackUrl, // fails if doesnt match hydra redirect-url :)
		Scopes:      []string{"openid", "offline", "email"},
	}

	var generateAuthCodeURL = func() (string, string) {

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

		authCodeURL := cliOAuthConfig.AuthCodeURL(
			state,
			codeChallenge, // Enable PKCE
			oauth2.SetAuthURLParam("audience", strings.Join([]string{""}, "+")),
			oauth2.SetAuthURLParam("nonce", string(nonce)),
			oauth2.SetAuthURLParam("prompt", strings.Join([]string{""}, "+")),
			oauth2.SetAuthURLParam("max_age", strconv.Itoa(maxAge)),
		)
		return authCodeURL, state
	}
	authCodeURL, initialState := generateAuthCodeURL()
	fmt.Println(authCodeURL, initialState)

	fmt.Println("Starting server")
	server := &http.Server{Addr: ":5556"}
	codeChannel := make(chan string)

	// Callback handler to get back from the browser
	http.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		fmt.Println("Received code:", code)
		if state == initialState {
			fmt.Println("state matches")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(fmt.Sprintf("code retrieved, code is: %s", code))); err != nil {
				fmt.Println("failed to write code retrieval", err)
				os.Exit(1)
			}

			codeChannel <- code
		} else {
			fmt.Println("state did not match, exiting")
			os.Exit(1)
		}
	})

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				fmt.Println("server closed safely")
			} else {
				fmt.Println("server interrupted unsafely, exiting")
				os.Exit(1)
			}
		}
	}()

	authCode := <-codeChannel
	if err := server.Shutdown(ctx); err != nil {
		fmt.Println("failed to shutdown server")
		os.Exit(1)
	}
	return authCode
}

// jimm represents the jimm server handling the authcode, exchanging it for a token using
// the client secret
//
// it only cares about the client id, client secret, token endpoint and redirect url.
// the redirect url will be checked to match that of the oauth client within hydra.
func jimm(ctx context.Context, authCode string, oauthClient oauthClient) *oauth2.Token {
	clientOAuthConfig := oauth2.Config{
		ClientID:     oauthClient.ClientId,
		ClientSecret: oauthClient.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenEndpoint,
		},
		RedirectURL: oauthClient.CallbackUrl, // fails if doesnt match hydra redirect-url :)
	}
	// Enable PKCE
	token, err := clientOAuthConfig.Exchange(ctx, authCode, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		fmt.Println("could not exchange auth code for access/id tokens", err)
		os.Exit(1)
	}

	// Get a new id token using access token
	// resp, err := clientOAuthConfig.Client(ctx, token).Get("http://127.0.0.1:4444/userinfo")
	// fmt.Println(err)
	// defer resp.Body.Close()
	// b, _ := io.ReadAll(resp.Body)
	// fmt.Println(string(b))
	return token
}

func main() {
	ctx := context.Background()
	oauthClient := setupHydra(ctx)
	clientAuthCode := cli(ctx, oauthClient)

	token := jimm(ctx, clientAuthCode, oauthClient)

	// Access token details:
	idToken := token.Extra("id_token")
	fmt.Println("Access Token:", token.AccessToken)
	fmt.Println("Refresh Token:", token.RefreshToken)
	fmt.Println("Token Type:", token.TokenType)
	fmt.Println("Expiry:", token.Expiry)
	fmt.Println("ID token: ", idToken)
}
