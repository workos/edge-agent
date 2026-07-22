// Copyright 2024 WorkOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package edge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testApiKey = "sk_test_edge_agent_key"

// warrant present in the seeded cache
const seededWarrant = "role:admin#member@user:alice@example.com"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	repo := NewMemoryRepository()
	if err := repo.Set(seededWarrant, 1); err != nil {
		t.Fatalf("failed to seed repository: %v", err)
	}
	server, err := NewServer(ServerConfig{
		ApiKey:     testApiKey,
		Port:       3000,
		Repository: repo,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return httptest.NewServer(server.Handler())
}

func postCheck(t *testing.T, baseURL, authHeader, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v2/check", strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// A request for the seeded warrant that an attacker-observable oracle would
// answer "Authorized" (HTTP 200) if it reached the handler.
const checkBody = `{"warrants":[{"objectType":"role","objectId":"admin","relation":"member","subject":{"objectType":"user","objectId":"alice@example.com"}}]}`

func TestCheckRejectsUnauthenticatedRequest(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	if status := postCheck(t, ts.URL, "", checkBody); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /v2/check: expected 401, got %d", status)
	}
}

func TestCheckRejectsWrongApiKey(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	if status := postCheck(t, ts.URL, "ApiKey wrong", checkBody); status != http.StatusUnauthorized {
		t.Fatalf("wrong-key /v2/check: expected 401, got %d", status)
	}
}

func TestCheckAllowsValidApiKey(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	status := postCheck(t, ts.URL, "ApiKey "+testApiKey, checkBody)
	if status != http.StatusOK {
		t.Fatalf("authenticated /v2/check: expected 200, got %d", status)
	}
}

func TestAuthorizeRejectsUnauthenticatedRequest(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v2/authorize", strings.NewReader(checkBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /v2/authorize: expected 401, got %d", resp.StatusCode)
	}
}

func TestHealthRemainsUnauthenticated(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health: expected 200, got %d", resp.StatusCode)
	}
}
