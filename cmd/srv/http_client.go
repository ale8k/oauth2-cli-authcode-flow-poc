package main

import "net/http"

// ServerHTTPClient is a struct that embeds http.Client
type ServerHTTPClient struct {
	*http.Client
	TimeoutSeconds int
}

// NewServerHTTPClient creates a new instance of http client with a custom timeout
func NewServerHTTPClient(timeoutSeconds int) *ServerHTTPClient {
	return &ServerHTTPClient{
		Client:         &http.Client{},
		TimeoutSeconds: timeoutSeconds,
	}
}
