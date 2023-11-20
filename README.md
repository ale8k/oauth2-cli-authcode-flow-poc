# oauth2-cli-authcode-flow-poc

A simple PoC using auth code flow within a CLI constrained application without the ability
to opt for device flow via Kratos and Hydra.

Getting started:
1. Run: `docker compose up`.
2. Run: `go run ./cmd/srv` to start the server.
3. Begin a login session via: `go run ./cmd/cli login`.

The demo environment creates a oauth2 client within hydra using the admin API, and as such no client credentials
need be setup. 