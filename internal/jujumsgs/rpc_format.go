package jujumsgs

import "encoding/json"

type Message struct {
	RequestID uint64                 `json:"request-id,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Version   int                    `json:"version,omitempty"`
	ID        string                 `json:"id,omitempty"`
	Request   string                 `json:"request,omitempty"`
	Params    json.RawMessage        `json:"params,omitempty"`
	Error     string                 `json:"error,omitempty"`
	ErrorCode string                 `json:"error-code,omitempty"`
	ErrorInfo map[string]interface{} `json:"error-info,omitempty"`
	Response  json.RawMessage        `json:"response,omitempty"`
}
