package middleware

import (
	"context"
	"net/http"
	"strings"
)

type key string

const (
	ContextTokenKey key = "ContextTokenKey"
)

func writeUnauthed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func IsAuthed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeUnauthed(w)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		ctx := context.WithValue(r.Context(), ContextTokenKey, token)

		req := r.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}
