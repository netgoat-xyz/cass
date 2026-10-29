package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type Cluster struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Secret      string `json:"secret"`
}

type Instance struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Endpoint     string     `json:"endpoint"`
	Status       string     `json:"status"`
	AgentKeyHint string     `json:"agent_key_hint,omitempty"`
	AgentKeyHash string     `json:"agent_key_hash,omitempty"`
	NodeFP       string     `json:"node_fingerprint,omitempty"`
	JoinedAt     *time.Time `json:"joined_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type JoinToken struct {
	ID        string     `json:"id"`
	NameHint  string     `json:"name_hint"`
	TokenHash string     `json:"token_hash"`
	TokenHint string     `json:"token_hint"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	UsedBy    string     `json:"used_by,omitempty"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
}

type Deployment struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instance_id"`
	Version    string    `json:"version"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type AuditEntry struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	CreatedAt time.Time `json:"created_at"`
}

type state struct {
	Cluster     Cluster        `json:"cluster"`
	Instances   []Instance     `json:"instances"`
	JoinTokens  []JoinToken    `json:"join_tokens"`
	Config      map[string]any `json:"config"`
	Deployments []Deployment   `json:"deployments"`
	Audit       []AuditEntry   `json:"audit"`
}

type Server struct {
	mu             sync.RWMutex
	state          state
	stateFile      string
	apiKey         string
	publicURL      string
	allowedOrigins []string
}

func NewServer(stateFile, apiKey, publicURL string) *Server {
	s := &Server{stateFile: stateFile, apiKey: apiKey, publicURL: strings.TrimRight(publicURL, "/")}
	s.normalize()
	_ = s.load()
	return s
}

// parseAllowedOrigins reads a comma-separated CORS allowlist.
func parseAllowedOrigins(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (s *Server) normalize() {
	if s.state.Instances == nil {
		s.state.Instances = []Instance{}
	}
	if s.state.JoinTokens == nil {
		s.state.JoinTokens = []JoinToken{}
	}
	if s.state.Deployments == nil {
		s.state.Deployments = []Deployment{}
	}
	if s.state.Audit == nil {
		s.state.Audit = []AuditEntry{}
	}
	if s.state.Config == nil {
		s.state.Config = map[string]any{}
	}
	if s.state.Cluster.ID == "" || s.state.Cluster.Secret == "" || s.state.Cluster.Fingerprint == "" {
		s.ensureClusterLocked()
	}
}

func (s *Server) ensureClusterLocked() {
	if s.state.Cluster.Secret == "" {
		s.state.Cluster.Secret = newSecret(32)
	}
	if s.state.Cluster.ID == "" {
		s.state.Cluster.ID = newID("cluster")
	}
	sum := sha256.Sum256([]byte(s.state.Cluster.Secret + ":" + s.state.Cluster.ID))
	s.state.Cluster.Fingerprint = formatFingerprint(sum[:])
}

func (s *Server) load() error {
	if s.stateFile == "" {
		s.normalize()
		return nil
	}
	data, err := os.ReadFile(s.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		s.normalize()
		_ = s.persistLocked()
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}
	s.normalize()
	return nil
}

func (s *Server) persistLocked() error {
	if s.stateFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.stateFile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.stateFile, data, 0o600)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func newSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

func hashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func formatFingerprint(raw []byte) string {
	hexed := strings.ToUpper(hex.EncodeToString(raw[:16]))
	parts := make([]string, 0, 8)
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":")
}

func tokenHint(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:10] + "…" + token[len(token)-4:]
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

func decodeJSON(r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

// authorized fails closed: an unset key locks the admin API rather than
// opening every endpoint to anyone who can reach the port.
func (s *Server) authorized(r *http.Request) bool {
	if s.apiKey == "" {
		return false
	}
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return subtle.ConstantTimeCompare([]byte(value), []byte(s.apiKey)) == 1
}

func (s *Server) joinBaseURL(r *http.Request) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return "http://127.0.0.1:8088"
	}
	return scheme + "://" + host
}

func (s *Server) clusterPublic(r *http.Request) map[string]string {
	return map[string]string{
		"id":          s.state.Cluster.ID,
		"fingerprint": s.state.Cluster.Fingerprint,
		"join_url":    s.joinBaseURL(r),
	}
}

// recoverPanics keeps a single malformed request from taking down the control plane.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic handling %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				errorResponse(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// allowedOrigin echoes only origins operators explicitly trust. A wildcard here
// would let any website drive the admin API from a victim's browser.
func (s *Server) allowedOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	for _, candidate := range s.allowedOrigins {
		if candidate == "*" || strings.EqualFold(candidate, origin) {
			return origin
		}
	}
	return ""
}

func (s *Server) handler() http.Handler {
	return recoverPanics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := s.allowedOrigin(r.Header.Get("Origin")); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/" {
			if r.Method != http.MethodGet {
				errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			jsonResponse(w, http.StatusOK, map[string]any{"status": "ok", "service": "netgoat-cas-api", "version": "1.1.0"})
			return
		}

		// Public join claim — authenticated by one-time join token, not admin key.
		if r.URL.Path == "/api/join" && r.Method == http.MethodPost {
			s.joinClaim(w, r)
			return
		}

		if !strings.HasPrefix(r.URL.Path, "/api/") || !s.authorized(r) {
			errorResponse(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.routeAPI(w, r)
	}))
}

func (s *Server) routeAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	parts := strings.Split(path, "/")
	switch parts[0] {
	case "overview":
		s.mu.RLock()
		defer s.mu.RUnlock()
		pending := 0
		for _, t := range s.state.JoinTokens {
			if !t.Revoked && t.UsedAt == nil && time.Now().Before(t.ExpiresAt) {
				pending++
			}
		}
		jsonResponse(w, http.StatusOK, map[string]int{
			"instances":     len(s.state.Instances),
			"deployments":   len(s.state.Deployments),
			"audit_entries": len(s.state.Audit),
			"pending_joins": pending,
		})
	case "cluster":
		if r.Method != http.MethodGet {
			errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		jsonResponse(w, http.StatusOK, s.clusterPublic(r))
	case "join-tokens":
		s.joinTokens(w, r, parts[1:])
	case "instances":
		s.instances(w, r, parts[1:])
	case "config":
		s.config(w, r)
	case "deployments":
		s.deployments(w, r)
	case "audit":
		if r.Method != http.MethodGet {
			errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		jsonResponse(w, http.StatusOK, s.state.Audit)
	default:
		errorResponse(w, http.StatusNotFound, "not found")
	}
}

type mintJoinInput struct {
	NameHint     string `json:"name_hint"`
	TTLHours     int    `json:"ttl_hours"`
	ExpectedName string `json:"expected_name"`
}

func (s *Server) joinTokens(w http.ResponseWriter, r *http.Request, rest []string) {
	if len(rest) == 0 && r.Method == http.MethodGet {
		s.mu.RLock()
		defer s.mu.RUnlock()
		out := make([]map[string]any, 0, len(s.state.JoinTokens))
		now := time.Now().UTC()
		for _, t := range s.state.JoinTokens {
			status := "pending"
			if t.Revoked {
				status = "revoked"
			} else if t.UsedAt != nil {
				status = "used"
			} else if now.After(t.ExpiresAt) {
				status = "expired"
			}
			out = append(out, map[string]any{
				"id":         t.ID,
				"name_hint":  t.NameHint,
				"token_hint": t.TokenHint,
				"expires_at": t.ExpiresAt,
				"used_at":    t.UsedAt,
				"used_by":    t.UsedBy,
				"revoked":    t.Revoked,
				"created_at": t.CreatedAt,
				"status":     status,
			})
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}

	if len(rest) == 0 && r.Method == http.MethodPost {
		var input mintJoinInput
		_ = decodeJSON(r, &input)
		nameHint := strings.TrimSpace(input.NameHint)
		if nameHint == "" {
			nameHint = strings.TrimSpace(input.ExpectedName)
		}
		if nameHint == "" {
			errorResponse(w, http.StatusBadRequest, "name_hint is required")
			return
		}
		ttl := input.TTLHours
		if ttl <= 0 {
			ttl = 24
		}
		if ttl > 168 {
			ttl = 168
		}

		plain := "ngj_" + newSecret(24)
		now := time.Now().UTC()
		token := JoinToken{
			ID:        newID("jt"),
			NameHint:  nameHint,
			TokenHash: hashSecret(plain),
			TokenHint: tokenHint(plain),
			ExpiresAt: now.Add(time.Duration(ttl) * time.Hour),
			CreatedAt: now,
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.JoinTokens = append(s.state.JoinTokens, token)
		s.recordLocked("join_token.minted", token.ID)
		if err := s.persistLocked(); err != nil {
			errorResponse(w, http.StatusInternalServerError, "state persistence failed")
			return
		}

		cluster := s.clusterPublic(r)
		command := fmt.Sprintf(
			"netgoat-agent join --cas %s --token %s --fingerprint %s --name %s",
			cluster["join_url"],
			plain,
			cluster["fingerprint"],
			nameHint,
		)
		jsonResponse(w, http.StatusCreated, map[string]any{
			"id":           token.ID,
			"token":        plain,
			"token_hint":   token.TokenHint,
			"name_hint":    token.NameHint,
			"expires_at":   token.ExpiresAt,
			"created_at":   token.CreatedAt,
			"cluster":      cluster,
			"join_command": command,
			"warning":      "Store this join token now. It is shown once and cannot be retrieved again.",
		})
		return
	}

	if len(rest) == 1 && r.Method == http.MethodDelete {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.state.JoinTokens {
			if s.state.JoinTokens[i].ID != rest[0] {
				continue
			}
			s.state.JoinTokens[i].Revoked = true
			s.recordLocked("join_token.revoked", rest[0])
			_ = s.persistLocked()
			jsonResponse(w, http.StatusOK, map[string]string{"status": "revoked", "id": rest[0]})
			return
		}
		errorResponse(w, http.StatusNotFound, "join token not found")
		return
	}

	errorResponse(w, http.StatusNotFound, "not found")
}

type joinClaimInput struct {
	Token              string `json:"token"`
	JoinToken          string `json:"join_token"`
	Name               string `json:"name"`
	Endpoint           string `json:"endpoint"`
	Fingerprint        string `json:"fingerprint"`
	ClusterFingerprint string `json:"cluster_fingerprint"`
	NodeFingerprint    string `json:"node_fingerprint"`
}

func normalizeFP(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
}

func (s *Server) joinClaim(w http.ResponseWriter, r *http.Request) {
	var input joinClaimInput
	if decodeJSON(r, &input) != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	plain := strings.TrimSpace(input.Token)
	if plain == "" {
		plain = strings.TrimSpace(input.JoinToken)
	}
	name := strings.TrimSpace(input.Name)
	endpoint := strings.TrimSpace(input.Endpoint)
	if plain == "" || name == "" || endpoint == "" {
		errorResponse(w, http.StatusBadRequest, "token, name, and endpoint are required")
		return
	}

	providedFP := input.Fingerprint
	if providedFP == "" {
		providedFP = input.ClusterFingerprint
	}
	// Required: when the fingerprint was optional, omitting it downgraded the
	// join to token-only, so an intercepted token alone could register a node.
	if providedFP == "" {
		errorResponse(w, http.StatusBadRequest, "cluster fingerprint is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if subtle.ConstantTimeCompare([]byte(normalizeFP(providedFP)), []byte(normalizeFP(s.state.Cluster.Fingerprint))) != 1 {
		errorResponse(w, http.StatusUnauthorized, "cluster fingerprint mismatch")
		return
	}

	now := time.Now().UTC()
	var token *JoinToken
	for i := range s.state.JoinTokens {
		t := &s.state.JoinTokens[i]
		if t.TokenHash != hashSecret(plain) {
			continue
		}
		token = t
		break
	}
	if token == nil {
		errorResponse(w, http.StatusUnauthorized, "invalid join token")
		return
	}
	if token.Revoked {
		errorResponse(w, http.StatusUnauthorized, "join token revoked")
		return
	}
	if token.UsedAt != nil {
		errorResponse(w, http.StatusConflict, "join token already used")
		return
	}
	if now.After(token.ExpiresAt) {
		errorResponse(w, http.StatusUnauthorized, "join token expired")
		return
	}

	agentKey := "nga_" + newSecret(24)
	joined := now
	item := Instance{
		ID:           newID("inst"),
		Name:         name,
		Endpoint:     endpoint,
		Status:       "joined",
		AgentKeyHint: tokenHint(agentKey),
		AgentKeyHash: hashSecret(agentKey),
		NodeFP:       strings.TrimSpace(input.NodeFingerprint),
		JoinedAt:     &joined,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	token.UsedAt = &joined
	token.UsedBy = item.ID
	s.state.Instances = append(s.state.Instances, item)
	s.recordLocked("instance.joined", item.ID)
	if err := s.persistLocked(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "state persistence failed")
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]any{
		"instance":  publicInstance(item),
		"agent_key": agentKey,
		"cluster":   s.clusterPublic(r),
		"warning":   "Store this agent key now. It is shown once and cannot be retrieved again.",
	})
}

func publicInstance(item Instance) Instance {
	item.AgentKeyHash = ""
	return item
}

type instanceInput struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func (s *Server) instances(w http.ResponseWriter, r *http.Request, rest []string) {
	if len(rest) == 0 && r.Method == http.MethodGet {
		s.mu.RLock()
		defer s.mu.RUnlock()
		out := make([]Instance, 0, len(s.state.Instances))
		for _, item := range s.state.Instances {
			out = append(out, publicInstance(item))
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}
	if len(rest) == 0 && r.Method == http.MethodPost {
		errorResponse(w, http.StatusBadRequest, "use POST /api/join-tokens then POST /api/join to register instances")
		return
	}
	if len(rest) != 1 {
		errorResponse(w, http.StatusNotFound, "not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Instances {
		if s.state.Instances[i].ID != rest[0] {
			continue
		}
		if r.Method == http.MethodGet {
			jsonResponse(w, http.StatusOK, publicInstance(s.state.Instances[i]))
			return
		}
		if r.Method != http.MethodPatch {
			errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var input instanceInput
		if decodeJSON(r, &input) != nil {
			errorResponse(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if input.Name != "" {
			s.state.Instances[i].Name = strings.TrimSpace(input.Name)
		}
		if input.Endpoint != "" {
			s.state.Instances[i].Endpoint = strings.TrimSpace(input.Endpoint)
		}
		s.state.Instances[i].UpdatedAt = time.Now().UTC()
		s.recordLocked("instance.updated", rest[0])
		_ = s.persistLocked()
		jsonResponse(w, http.StatusOK, publicInstance(s.state.Instances[i]))
		return
	}
	errorResponse(w, http.StatusNotFound, "instance not found")
}

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		jsonResponse(w, http.StatusOK, s.state.Config)
		return
	}
	if r.Method != http.MethodPut {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var value map[string]any
	if decodeJSON(r, &value) != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON object")
		return
	}
	s.state.Config = value
	s.recordLocked("config.updated", "config")
	if err := s.persistLocked(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "state persistence failed")
		return
	}
	jsonResponse(w, http.StatusOK, s.state.Config)
}

type deploymentInput struct {
	InstanceID string `json:"instance_id"`
	Version    string `json:"version"`
}

func (s *Server) deployments(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		jsonResponse(w, http.StatusOK, s.state.Deployments)
		return
	}
	if r.Method != http.MethodPost {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var input deploymentInput
	if decodeJSON(r, &input) != nil || input.InstanceID == "" || input.Version == "" {
		errorResponse(w, http.StatusBadRequest, "instance_id and version are required")
		return
	}
	item := Deployment{ID: newID("deploy"), InstanceID: input.InstanceID, Version: input.Version, Status: "queued", CreatedAt: time.Now().UTC()}
	s.state.Deployments = append(s.state.Deployments, item)
	s.recordLocked("deployment.queued", item.ID)
	if err := s.persistLocked(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "state persistence failed")
		return
	}
	jsonResponse(w, http.StatusAccepted, item)
}

func (s *Server) recordLocked(action, resource string) {
	s.state.Audit = append(s.state.Audit, AuditEntry{ID: newID("audit"), Action: action, Resource: resource, CreatedAt: time.Now().UTC()})
}

func main() {
	addr := os.Getenv("CAS_ADDR")
	if addr == "" {
		addr = ":8088"
	}
	stateFile := os.Getenv("CAS_STATE_FILE")
	if stateFile == "" {
		stateFile = filepath.Join("data", "cas.json")
	}
	apiKey := strings.TrimSpace(os.Getenv("CAS_API_KEY"))
	if apiKey == "" {
		log.Fatal("CAS_API_KEY is required: refusing to start an unauthenticated control-plane API")
	}

	server := NewServer(stateFile, apiKey, os.Getenv("CAS_PUBLIC_URL"))
	server.allowedOrigins = parseAllowedOrigins(os.Getenv("CAS_ALLOWED_ORIGINS"))

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("CAS API listening on %s (cluster %s)", addr, server.state.Cluster.ID)
	log.Fatal(srv.ListenAndServe())
}
