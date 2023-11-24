package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ale8k/authcode-flow-go-poc/internal/jujumsgs"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "app",
	Short: "A CLI app with login and ping commands",
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Simulate user login",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Opening a WebSocket to the server...")
		conn, _, err := websocket.DefaultDialer.Dial("ws://localhost:8080/ws", nil)
		if err != nil {
			log.Fatal("Error opening WebSocket:", err)
		}
		defer conn.Close()

		for {
			dummyHardcodedRequestId := 69
			/*
				Phase 1 of login
			*/
			fmt.Println("----- Starting phase 1 of login -----")
			// Start login method
			p := map[string]string{
				"login-type":  "jimm",
				"login-state": "request-auth-code-url",
			}
			b, _ := json.Marshal(p)
			if err := conn.WriteJSON(jujumsgs.Message{
				RequestID: uint64(dummyHardcodedRequestId),
				Type:      "Admin",
				Version:   69,
				Request:   "Login",
				Params:    b,
			}); err != nil {
				log.Println("Failed to write login message: ", err)
				return
			}

			// Read response, and get auth code url
			loginResp := jujumsgs.Message{}
			if err := conn.ReadJSON(&loginResp); err != nil {
				log.Println("Failed to read login response: ", err)
				return
			}

			respRequest := map[string]string{}
			b, _ = loginResp.Response.MarshalJSON()
			if err := json.Unmarshal(b, &respRequest); err != nil {
				log.Println("Failed to unmarshal login response: ", err)
				return
			}

			authCodeUrl := respRequest["auth-code-url"]
			initialState := respRequest["state"]

			// Make channel to retrieve auth code
			authCodeChannel := make(chan string)

			// Setup server to handle flow
			srv := handleLocalRedirectionInterfaceCallback(initialState, authCodeChannel)

			// Tell user to login and wait for auth code retrieval
			fmt.Println("Please go this url to login: ", authCodeUrl)
			authCode := <-authCodeChannel

			// Shut server down
			if err := srv.Shutdown(context.Background()); err != nil {
				fmt.Println("failed to shutdown server")
				return
			}

			/*
				Phase 2 of login
			*/
			fmt.Println("----- Starting phase 2 of login -----")
			p = map[string]string{
				"login-type":  "jimm",
				"login-state": "exchange-auth-code",
				"auth-code":   authCode,
			}
			b, _ = json.Marshal(p)
			if err := conn.WriteJSON(jujumsgs.Message{
				RequestID: uint64(dummyHardcodedRequestId),
				Type:      "Admin",
				Version:   69,
				Request:   "Login",
				Params:    b,
			}); err != nil {
				log.Println("Failed to write login message: ", err)
				return
			}

			// Read response, and get access token
			loginResp = jujumsgs.Message{}
			if err := conn.ReadJSON(&loginResp); err != nil {
				log.Println("Failed to read login response: ", err)
				return
			}

			respRequest = map[string]string{}
			b, _ = loginResp.Response.MarshalJSON()
			if err := json.Unmarshal(b, &respRequest); err != nil {
				log.Println("Failed to unmarshal login response: ", err)
				return
			}
			fmt.Println(loginResp)

			// Get the access token
			token := respRequest["access-token"]
			fmt.Println(respRequest, "<-------------")
			file, _ := os.Create("./accesstoken.txt")
			file.WriteString(token)
			file.Close()
			// Finish up socket
			time.Sleep(10 * time.Second)
			conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Connection closed"), time.Now().Add(time.Hour))

		}
	},
}

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Open a WebSocket to a server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Opening a WebSocket to the server...")
		conn, _, err := websocket.DefaultDialer.Dial("ws://localhost:8080/ws", nil)
		if err != nil {
			log.Fatal("Error opening WebSocket:", err)
		}
		defer conn.Close()

		if err := conn.WriteJSON(jujumsgs.Message{
			RequestID: 0,
			Type:      "",
			Version:   0,
			ID:        "",
			Request:   "",
			Params:    []byte{},
			Error:     "",
			ErrorCode: "",
			ErrorInfo: map[string]interface{}{
				"": nil,
			},
			Response: []byte{},
		}); err != nil {
			log.Println("Failed to write json: ", err)
			return
		}

		err = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Connection closed"), time.Now().Add(time.Hour))
		if err != nil {
			log.Println("Error sending close message:", err)
			return
		}
	},
}

func handleLocalRedirectionInterfaceCallback(initialState string, codeChannel chan<- string) *http.Server {
	fmt.Println("Starting server")
	server := &http.Server{Addr: ":5556"}

	// Callback handler to get back from the browser
	http.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		fmt.Println("Received code:", code)
		if state == initialState {
			fmt.Println("state matches")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("login complete, please close browser")); err != nil {
				fmt.Println("failed to write code retrieval", err)
				return
			}

			codeChannel <- code
		} else {
			fmt.Println("state did not match, exiting")
			return
		}
	})

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				fmt.Println("server closed safely")
			} else {
				fmt.Println("server interrupted unsafely, exiting")
				return
			}
		}
	}()

	return server
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(pingCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
