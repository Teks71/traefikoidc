package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Config holds the configuration for the OIDC middleware.
// It provides all necessary settings to configure OpenID Connect authentication
// with various providers like Auth0, Logto, or any standard OIDC provider.
type Config struct {
	// ProviderURL is the base URL of the OIDC provider (required)
	// Example: https://accounts.google.com
	ProviderURL string `json:"providerURL"`

	// RevocationURL is the endpoint for revoking tokens (optional)
	// If not provided, it will be discovered from provider metadata
	RevocationURL string `json:"revocationURL"`

	// EnablePKCE enables Proof Key for Code Exchange (PKCE) for the authorization code flow (optional)
	// This enhances security but might not be supported by all OIDC providers
	// Default: false
	EnablePKCE bool `json:"enablePKCE"`

	// CallbackURL is the path where the OIDC provider will redirect after authentication (required)
	// Example: /oauth2/callback
	CallbackURL string `json:"callbackURL"`

	// LogoutURL is the path for handling logout requests (optional)
	// If not provided, it will be set to CallbackURL + "/logout"
	LogoutURL string `json:"logoutURL"`

	// ClientID is the OAuth 2.0 client identifier (required)
	ClientID string `json:"clientID"`

	// ClientSecret is the OAuth 2.0 client secret (required)
	ClientSecret string `json:"clientSecret"`

	// Scopes defines the OAuth 2.0 scopes to request (optional)
	// Defaults to ["openid", "profile", "email"] if not provided
	Scopes []string `json:"scopes"`

	// LogLevel sets the logging verbosity (optional)
	// Valid values: "debug", "info", "error"
	// Default: "info"
	LogLevel string `json:"logLevel"`

	// SessionEncryptionKey is used to encrypt session data (required)
	// Must be a secure random string
	SessionEncryptionKey string `json:"sessionEncryptionKey"`

	// ForceHTTPS forces the use of HTTPS for all URLs (optional)
	// Default: false
	ForceHTTPS bool `json:"forceHTTPS"`

	// RateLimit sets the maximum number of requests per second (optional)
	// Default: 100
	RateLimit int `json:"rateLimit"`

	// ExcludedURLs lists paths that bypass authentication (optional)
	// Example: ["/health", "/metrics"]
	ExcludedURLs []string `json:"excludedURLs"`

	// AllowedUserDomains restricts access to specific email domains (optional)
	// Example: ["company.com", "subsidiary.com"]
	AllowedUserDomains []string `json:"allowedUserDomains"`

	// AllowedRolesAndGroups restricts access to users with specific roles or groups (optional)
	// Example: ["admin", "developer"]
	AllowedRolesAndGroups []string `json:"allowedRolesAndGroups"`

	// OIDCEndSessionURL is the provider's end session endpoint (optional)
	// If not provided, it will be discovered from provider metadata
	OIDCEndSessionURL string `json:"oidcEndSessionURL"`

	// PostLogoutRedirectURI is the URL to redirect to after logout (optional)
	// Default: "/"
	PostLogoutRedirectURI string `json:"postLogoutRedirectURI"`

	// HTTPClient allows customizing the HTTP client used for OIDC operations (optional)
	HTTPClient *http.Client

	// ForwardedClaims configures additional claims that should be forwarded to the upstream service as headers.
	ForwardedClaims map[string]*ForwardedClaimTarget `json:"forwardedClaims"`
}

var reservedForwardedHeaders = map[string]struct{}{
	strings.ToLower("X-Forwarded-User"):        {},
	strings.ToLower("X-User-Groups"):           {},
	strings.ToLower("X-User-Roles"):            {},
	strings.ToLower("X-Auth-Request-Redirect"): {},
	strings.ToLower("X-Auth-Request-User"):     {},
	strings.ToLower("X-Auth-Request-Token"):    {},
}

// ForwardedClaimTarget defines how a single claim should be forwarded to downstream services.
// It supports optional HMAC signing or encryption for additional security.
type ForwardedClaimTarget struct {
	Header     string                          `json:"header"`
	HMAC       *ForwardedClaimHMACConfig       `json:"hmac,omitempty"`
	Encryption *ForwardedClaimEncryptionConfig `json:"encryption,omitempty"`
}

// ForwardedClaimHMACConfig specifies how to sign forwarded claim values.
type ForwardedClaimHMACConfig struct {
	Secret    string `json:"secret"`
	Header    string `json:"header"`
	Algorithm string `json:"algorithm"`
}

// ForwardedClaimEncryptionConfig specifies how to encrypt forwarded claim values.
type ForwardedClaimEncryptionConfig struct {
	Key    string `json:"key"`
	Header string `json:"header"`
}

// UnmarshalJSON allows the forwarded claim target to be defined as either a string (header name)
// or a structured object with additional security configuration.
func (f *ForwardedClaimTarget) UnmarshalJSON(data []byte) error {
	type alias ForwardedClaimTarget
	if len(data) == 0 {
		return nil
	}

	if data[0] == '"' {
		var header string
		if err := json.Unmarshal(data, &header); err != nil {
			return err
		}
		f.Header = header
		return nil
	}

	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*f = ForwardedClaimTarget(a)
	return nil
}

const (
	// DefaultRateLimit defines the default rate limit for requests per second
	DefaultRateLimit = 100

	// MinRateLimit defines the minimum allowed rate limit to prevent DOS
	MinRateLimit = 10

	// DefaultLogLevel defines the default logging level
	DefaultLogLevel = "info"

	// MinSessionEncryptionKeyLength defines the minimum length for session encryption key
	MinSessionEncryptionKeyLength = 32
)

// CreateConfig creates a new Config with secure default values.
// Default values are set for optional fields:
//   - Scopes: ["openid", "profile", "email"]
//   - LogLevel: "info"
//   - LogoutURL: CallbackURL + "/logout"
//   - RateLimit: 100 requests per second
//   - PostLogoutRedirectURI: "/"
//   - ForceHTTPS: true (for security)
//   - EnablePKCE: false (PKCE is opt-in)
func CreateConfig() *Config {
	c := &Config{
		Scopes:     []string{"openid", "profile", "email"},
		LogLevel:   DefaultLogLevel,
		RateLimit:  DefaultRateLimit,
		ForceHTTPS: true,  // Secure by default
		EnablePKCE: false, // PKCE is opt-in
	}

	return c
}

// Validate performs validation checks on the Config.
// It ensures all required fields are set and have valid values.
// Returns an error if any validation check fails.
func (c *Config) Validate() error {
	// Validate provider URL
	if c.ProviderURL == "" {
		return fmt.Errorf("providerURL is required")
	}
	if !isValidSecureURL(c.ProviderURL) {
		return fmt.Errorf("providerURL must be a valid HTTPS URL")
	}

	// Validate callback URL
	if c.CallbackURL == "" {
		return fmt.Errorf("callbackURL is required")
	}
	if !strings.HasPrefix(c.CallbackURL, "/") {
		return fmt.Errorf("callbackURL must start with /")
	}

	// Validate client credentials
	if c.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}

	// Validate session encryption key
	if c.SessionEncryptionKey == "" {
		return fmt.Errorf("sessionEncryptionKey is required")
	}
	if len(c.SessionEncryptionKey) < MinSessionEncryptionKeyLength {
		return fmt.Errorf("sessionEncryptionKey must be at least %d characters long", MinSessionEncryptionKeyLength)
	}

	// Validate log level
	if c.LogLevel != "" && !isValidLogLevel(c.LogLevel) {
		return fmt.Errorf("logLevel must be one of: debug, info, error")
	}

	// Validate excluded URLs
	for _, url := range c.ExcludedURLs {
		if !strings.HasPrefix(url, "/") {
			return fmt.Errorf("excluded URL must start with /: %s", url)
		}
		if strings.Contains(url, "..") {
			return fmt.Errorf("excluded URL must not contain path traversal: %s", url)
		}
		if strings.Contains(url, "*") {
			return fmt.Errorf("excluded URL must not contain wildcards: %s", url)
		}
	}

	// Validate revocation URL if set
	if c.RevocationURL != "" && !isValidSecureURL(c.RevocationURL) {
		return fmt.Errorf("revocationURL must be a valid HTTPS URL")
	}

	// Validate end session URL if set
	if c.OIDCEndSessionURL != "" && !isValidSecureURL(c.OIDCEndSessionURL) {
		return fmt.Errorf("oidcEndSessionURL must be a valid HTTPS URL")
	}

	// Validate post-logout redirect URI if set
	if c.PostLogoutRedirectURI != "" && c.PostLogoutRedirectURI != "/" {
		if !isValidSecureURL(c.PostLogoutRedirectURI) && !strings.HasPrefix(c.PostLogoutRedirectURI, "/") {
			return fmt.Errorf("postLogoutRedirectURI must be either a valid HTTPS URL or start with /")
		}
	}

	// Validate rate limit
	if c.RateLimit < MinRateLimit {
		return fmt.Errorf("rateLimit must be at least %d", MinRateLimit)
	}

	// Validate forwarded claims configuration
	if len(c.ForwardedClaims) > 0 {
		usedHeaders := make(map[string]string)
		for claimPath, target := range c.ForwardedClaims {
			if target == nil {
				return fmt.Errorf("forwardedClaims entry for %s is invalid", claimPath)
			}

			if strings.TrimSpace(claimPath) == "" {
				return fmt.Errorf("forwardedClaims keys must not be empty")
			}

			headerName := strings.TrimSpace(target.Header)
			if headerName == "" {
				return fmt.Errorf("forwardedClaims[%s] must specify a header name", claimPath)
			}

			if err := c.validateForwardedHeader(claimPath, headerName, usedHeaders); err != nil {
				return err
			}

			if target.HMAC != nil {
				if strings.TrimSpace(target.HMAC.Secret) == "" {
					return fmt.Errorf("forwardedClaims[%s] hmac secret must not be empty", claimPath)
				}

				if target.HMAC.Algorithm != "" && !strings.EqualFold(target.HMAC.Algorithm, "HS256") {
					return fmt.Errorf("forwardedClaims[%s] hmac algorithm must be HS256", claimPath)
				}

				if _, err := decodeKeyMaterial(target.HMAC.Secret); err != nil {
					return fmt.Errorf("forwardedClaims[%s] hmac secret is invalid: %w", claimPath, err)
				}

				signatureHeader := target.HMAC.Header
				if signatureHeader == "" {
					signatureHeader = headerName + "-Signature"
				}
				if err := c.validateForwardedHeader(claimPath, signatureHeader, usedHeaders); err != nil {
					return err
				}
			}

			if target.Encryption != nil {
				if strings.TrimSpace(target.Encryption.Key) == "" {
					return fmt.Errorf("forwardedClaims[%s] encryption key must not be empty", claimPath)
				}

				if _, err := decodeEncryptionKey(target.Encryption.Key); err != nil {
					return fmt.Errorf("forwardedClaims[%s] encryption key is invalid: %w", claimPath, err)
				}

				encryptionHeader := target.Encryption.Header
				if encryptionHeader == "" {
					encryptionHeader = headerName + "-Encrypted"
				}
				if err := c.validateForwardedHeader(claimPath, encryptionHeader, usedHeaders); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Config) validateForwardedHeader(claimPath, headerName string, usedHeaders map[string]string) error {
	normalized := strings.ToLower(headerName)
	if _, reserved := reservedForwardedHeaders[normalized]; reserved {
		return fmt.Errorf("forwardedClaims[%s] header %s conflicts with a reserved header", claimPath, headerName)
	}

	if existing, exists := usedHeaders[normalized]; exists {
		claims := []string{existing, claimPath}
		sort.Strings(claims)
		return fmt.Errorf("forwardedClaims header %s is already used for claims %s and %s", headerName, claims[0], claims[1])
	}

	usedHeaders[normalized] = claimPath
	return nil
}

func decodeKeyMaterial(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("key material is empty")
	}

	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
		return decoded, nil
	}

	return []byte(value), nil
}

func decodeEncryptionKey(value string) ([]byte, error) {
	key, err := decodeKeyMaterial(value)
	if err != nil {
		return nil, err
	}

	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, fmt.Errorf("encryption key must be 16, 24, or 32 bytes long, got %d", len(key))
	}
}

// isValidSecureURL checks if the provided string is a valid HTTPS URL
func isValidSecureURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// isValidLogLevel checks if the provided log level is valid
func isValidLogLevel(level string) bool {
	return level == "debug" || level == "info" || level == "error"
}

// Logger provides structured logging capabilities with different severity levels.
// It supports error, info, and debug levels with appropriate output streams
// and formatting for each level.
type Logger struct {
	// logError handles error-level messages, writing to stderr
	logError *log.Logger
	// logInfo handles informational messages, writing to stdout
	logInfo *log.Logger
	// logDebug handles debug-level messages, writing to stdout when debug is enabled
	logDebug *log.Logger
}

// NewLogger creates a new Logger with the specified log level.
// The log level determines which messages are output:
//   - "debug": Outputs all messages (debug, info, error)
//   - "info": Outputs info and error messages
//   - "error": Outputs only error messages
//
// Error messages are always written to stderr, while info and debug
// messages are written to stdout when enabled.
func NewLogger(logLevel string) *Logger {
	logError := log.New(io.Discard, "ERROR: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: TraefikOidcPlugin: ", log.Ldate|log.Ltime)

	logError.SetOutput(os.Stderr)

	if logLevel == "debug" || logLevel == "info" {
		logInfo.SetOutput(os.Stdout)
	}
	if logLevel == "debug" {
		logDebug.SetOutput(os.Stdout)
	}

	return &Logger{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

// Info logs an informational message.
// These messages are intended for general operational information
// and are written to stdout.
func (l *Logger) Info(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debug logs a debug message.
// These messages are only output when debug level logging is enabled
// and are intended for detailed troubleshooting information.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Error logs an error message.
// These messages indicate problems that need attention and are
// always written to stderr regardless of the log level.
func (l *Logger) Error(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// Infof logs an informational message using Printf formatting.
// These messages are intended for general operational information
// and are written to stdout.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debugf logs a debug message using Printf formatting.
// These messages are only output when debug level logging is enabled
// and are intended for detailed troubleshooting information.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Errorf logs an error message using Printf formatting.
// These messages indicate problems that need attention and are
// always written to stderr regardless of the log level.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// handleError writes an error message to both the HTTP response and the error log.
// It ensures consistent error handling across the middleware by logging the error
// and sending an appropriate HTTP response to the client.
func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error(message)
	http.Error(w, message, code)
}
