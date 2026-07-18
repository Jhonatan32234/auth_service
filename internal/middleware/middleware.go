package middleware

import (
	"log"
	"net/http"
	"sync"
	"time"

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
	mu       sync.RWMutex
	clients  map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
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
func SignatureOrAPIKeyMiddleware(expectedKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signature := r.Header.Get("X-Signature")
			keyID := r.Header.Get("X-Key-ID")

			if signature != "" && keyID != "" {
				// Verificación con firma asimétrica
				// La implementación completa se integrará con pkg/signing
				// Por ahora, si hay firma pero no podemos verificar, rechazamos
				http.Error(w, `{"error":"firma asimétrica no soportada aún"}`, http.StatusForbidden)
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