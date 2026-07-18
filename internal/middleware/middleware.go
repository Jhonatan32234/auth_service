package middleware

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"saferoute-auth/internal/security"

	"golang.org/x/time/rate"
)

// ── Security Headers ──────────────────────────────────────────────────────────

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ── Logging ───────────────────────────────────────────────────────────────────

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

// ── Rate Limiting ─────────────────────────────────────────────────────────────

type IPRateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*rate.Limiter
	rate    rate.Limit
	burst   int
}

func NewIPRateLimiter(r rate.Limit, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		clients: make(map[string]*rate.Limiter),
		rate:    r,
		burst:   burst,
	}
}

func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	l.mu.RLock()
	limiter, exists := l.clients[ip]
	l.mu.RUnlock()

	if exists {
		return limiter
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	limiter = rate.NewLimiter(l.rate, l.burst)
	l.clients[ip] = limiter
	return limiter
}

func RateLimitMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if !limiter.GetLimiter(ip).Allow() {
				http.Error(w, `{"error":"demasiadas solicitudes"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── Signature or API Key Middleware ───────────────────────────────────────────

// SignatureOrAPIKeyMiddleware verifica primero firma Ed25519 (X-Signature + X-Key-ID),
// y si no está presente, cae a la API Key tradicional (X-Internal-API-Key).
func SignatureOrAPIKeyMiddleware(servicePublicKey ed25519.PublicKey, expectedKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signature := r.Header.Get("X-Signature")
			keyID := r.Header.Get("X-Key-ID")

			if signature != "" && keyID != "" {
				if servicePublicKey == nil {
					http.Error(w, `{"error":"clave pública de servicio no configurada"}`, http.StatusInternalServerError)
					return
				}

				// Leer el body sin consumirlo permanentemente
				var bodyBytes []byte
				if r.Body != nil {
					var err error
					bodyBytes, err = io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, `{"error":"error leyendo cuerpo de petición"}`, http.StatusBadRequest)
						return
					}
					// Restaurar el body
					r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}

				timestampStr := r.Header.Get("X-Timestamp")
				timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
				if err != nil {
					http.Error(w, `{"error":"X-Timestamp inválido o faltante"}`, http.StatusForbidden)
					return
				}

				// Verificar la firma usando el módulo security
				valid, err := security.VerifyRequest(servicePublicKey, r.Method, r.URL.Path, timestamp, bodyBytes, signature)
				if err != nil || !valid {
					errMsg := "firma de petición inválida"
					if err != nil {
						errMsg = errMsg + ": " + err.Error()
					}
					http.Error(w, `{"error":"`+errMsg+`"}`, http.StatusForbidden)
					return
				}

				next.ServeHTTP(w, r)
				return
			}

			// Fallback: API Key tradicional
			apiKey := r.Header.Get("X-Internal-API-Key")
			if apiKey == "" || apiKey != expectedKey {
				http.Error(w, `{"error":"acceso interno no autorizado"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
