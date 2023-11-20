package main

type WellKnownConfiguration struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	JwksURI                                string   `json:"jwks_uri"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ClaimsSupported                        []string `json:"claims_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint"`
	ScopesSupported                        []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	UserinfoSigningAlgValuesSupported      []string `json:"userinfo_signing_alg_values_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	IDTokenSignedResponseAlg               []string `json:"id_token_signed_response_alg"`
	UserinfoSignedResponseAlg              []string `json:"userinfo_signed_response_alg"`
	RequestParameterSupported              bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported           bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration          bool     `json:"require_request_uri_registration"`
	ClaimsParameterSupported               bool     `json:"claims_parameter_supported"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	BackchannelLogoutSupported             bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported      bool     `json:"backchannel_logout_session_supported"`
	FrontchannelLogoutSupported            bool     `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported     bool     `json:"frontchannel_logout_session_supported"`
	EndSessionEndpoint                     string   `json:"end_session_endpoint"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	CredentialsEndpointDraft00             string   `json:"credentials_endpoint_draft_00"`
	CredentialsSupportedDraft00            []struct {
		Format                               string   `json:"format"`
		Types                                []string `json:"types"`
		CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported"`
		CryptographicSuitesSupported         []string `json:"cryptographic_suites_supported"`
	} `json:"credentials_supported_draft_00"`
}
