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
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/warrant-dev/warrant/pkg/service"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (rw *loggingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// authMiddleware enforces that inbound requests present the configured API key
// via an "Authorization: ApiKey <key>" header, matching the WorkOS cloud API.
// Requests without a valid credential are rejected with 401 before any handler
// runs. If no API key is configured, the agent fails closed and rejects all
// requests rather than serving the authorization graph anonymously.
func authMiddleware(apiKey string, next http.Handler) http.Handler {
	expected := fmt.Sprintf("ApiKey %s", apiKey)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("Authorization")
		if apiKey == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			service.SendErrorResponse(w, NewUnauthorized())
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		rw := NewLoggingResponseWriter(w)
		next.ServeHTTP(rw, r)
		elapsedTime := time.Since(startTime)

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		log.Println(
			fmt.Sprintf(
				"%s - \"%s %s %s\" %s %d %v",
				host,
				r.Method,
				r.RequestURI,
				r.Proto,
				r.UserAgent(),
				rw.statusCode,
				elapsedTime,
			),
		)
	})
}
