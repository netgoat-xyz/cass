package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthDoesNotRequireAuth(t *testing.T) {
	s := NewServer("", "secret", "")
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUIAPIRequiresBearerKey(t *testing.T) {
	s := NewServer("", "secret", "http://cas.test")
	for _, auth := range []string{"", "Bearer wrong"} {
		r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("auth=%q status=%d", auth, w.Code)
		}
	}
}

func TestAPIKeyMustBeConfigured(t *testing.T) {
	s := NewServer("", "", "")
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unset API key must fail closed, got status=%d", w.Code)
	}
}

func TestJoinTokenAndClaimFlow(t *testing.T) {
	s := NewServer("", "secret", "http://cas.test:8088")

	mint := httptest.NewRequest(http.MethodPost, "/api/join-tokens", bytes.NewBufferString(`{"name_hint":"edge-one","ttl_hours":2}`))
	mint.Header.Set("Content-Type", "application/json")
	mint.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, mint)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint status=%d body=%s", w.Code, w.Body.String())
	}

	var minted struct {
		Token   string `json:"token"`
		Cluster struct {
			Fingerprint string `json:"fingerprint"`
			JoinURL     string `json:"join_url"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Token == "" || minted.Cluster.Fingerprint == "" {
		t.Fatalf("missing token/fingerprint: %+v", minted)
	}
	if minted.Cluster.JoinURL != "http://cas.test:8088" {
		t.Fatalf("join_url=%s", minted.Cluster.JoinURL)
	}

	body, _ := json.Marshal(map[string]string{
		"token":       minted.Token,
		"name":        "edge-one",
		"endpoint":    "https://edge.example",
		"fingerprint": minted.Cluster.Fingerprint,
	})
	claim := httptest.NewRequest(http.MethodPost, "/api/join", bytes.NewBuffer(body))
	claim.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, claim)
	if w.Code != http.StatusCreated {
		t.Fatalf("claim status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"agent_key":"nga_`) {
		t.Fatalf("expected agent key in body=%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"joined"`) {
		t.Fatalf("expected joined status body=%s", w.Body.String())
	}

	// Token is one-time.
	reuse := httptest.NewRequest(http.MethodPost, "/api/join", bytes.NewBuffer(body))
	reuse.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, reuse)
	if w.Code != http.StatusConflict {
		t.Fatalf("reuse status=%d body=%s", w.Code, w.Body.String())
	}

	deploy := httptest.NewRequest(http.MethodPost, "/api/deployments", bytes.NewBufferString(`{"instance_id":"inst-test","version":"1.2.3"}`))
	deploy.Header.Set("Content-Type", "application/json")
	deploy.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, deploy)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"queued"`) {
		t.Fatalf("deploy status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestJoinRejectsFingerprintMismatch(t *testing.T) {
	s := NewServer("", "secret", "")
	mint := httptest.NewRequest(http.MethodPost, "/api/join-tokens", bytes.NewBufferString(`{"name_hint":"edge"}`))
	mint.Header.Set("Content-Type", "application/json")
	mint.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, mint)
	var minted struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &minted)

	body, _ := json.Marshal(map[string]string{
		"token":       minted.Token,
		"name":        "edge",
		"endpoint":    "https://edge.example",
		"fingerprint": "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
	})
	claim := httptest.NewRequest(http.MethodPost, "/api/join", bytes.NewBuffer(body))
	claim.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, claim)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestJoinRequiresFingerprint(t *testing.T) {
	s := NewServer("", "secret", "")
	mint := httptest.NewRequest(http.MethodPost, "/api/join-tokens", bytes.NewBufferString(`{"name_hint":"edge"}`))
	mint.Header.Set("Content-Type", "application/json")
	mint.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, mint)
	var minted struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &minted)

	// A valid token with no fingerprint must not be enough to join.
	body, _ := json.Marshal(map[string]string{
		"token":    minted.Token,
		"name":     "edge",
		"endpoint": "https://edge.example",
	})
	claim := httptest.NewRequest(http.MethodPost, "/api/join", bytes.NewBuffer(body))
	claim.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, claim)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
