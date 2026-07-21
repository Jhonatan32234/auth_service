package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/time/rate"

	"saferoute-auth/internal/auth"
	"saferoute-auth/internal/config"
	"saferoute-auth/internal/database"
	"saferoute-auth/internal/middleware"
	"saferoute-auth/internal/security"
)

func main() {
	// ── Configuración ──────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Error cargando configuración:", err)
	}

	encryptionKey, err := security.DecodeEncryptionKey(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("Error con ENCRYPTION_KEY: %v. Asegúrate de que sea base64 de 32 bytes.", err)
	}
	log.Println("✅ Clave de cifrado AES-256 cargada correctamente")

	jwtPrivateKeyBytes, err := base64.StdEncoding.DecodeString(cfg.JWTPrivateKey)
	if err != nil {
		log.Fatalf("Error decodificando JWT_PRIVATE_KEY: %v. Debe ser base64 de 64 bytes.", err)
	}
	jwtPrivateKey := ed25519.PrivateKey(jwtPrivateKeyBytes)

	servicePublicKeyBytes, err := base64.StdEncoding.DecodeString(cfg.ServicePublicKey)
	if err != nil {
		log.Fatalf("Error decodificando SERVICE_PUBLIC_KEY: %v. Debe ser base64 de 32 bytes.", err)
	}
	servicePublicKey := ed25519.PublicKey(servicePublicKeyBytes)

	log.Println("✅ Claves asimétricas Ed25519 cargadas correctamente")

	// ── Base de datos ──────────────────────────────────────────────────────────
	if err := database.Connect(cfg.DatabaseURL); err != nil {
		log.Fatal("Error conectando a base de datos:", err)
	}
	defer database.Close()
	db := database.DB

	// ── Repositorios ───────────────────────────────────────────────────────────
	userRepo := auth.NewRepository(db)

	// ── Servicios ──────────────────────────────────────────────────────────────
	authSvc := auth.NewAuthService(userRepo, encryptionKey, jwtPrivateKey)

	// ── Handlers ───────────────────────────────────────────────────────────────
	authHandler := auth.NewHandler(authSvc, cfg.JWTSecret)

	// ── Rate limiter ───────────────────────────────────────────────────────────
	limiter := middleware.NewIPRateLimiter(
		rate.Limit(cfg.RateLimit.RequestsPerSecond),
		cfg.RateLimit.Burst,
	)

	// ── Router ─────────────────────────────────────────────────────────────────
	r := mux.NewRouter()
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.LoggingMiddleware)
	r.Use(middleware.RateLimitMiddleware(limiter))

	// ── Rutas del Auth Service ─────────────────────────────────────────────────
	// Rutas públicas
	r.HandleFunc("/auth/login", authHandler.LoginHandler()).Methods("POST")
	r.HandleFunc("/auth/register", authHandler.RegisterHandler()).Methods("POST")

	// Rutas internas (protegidas con firma Ed25519 o API Key)
	internal := r.PathPrefix("/auth/internal").Subrouter()
	internal.Use(middleware.SignatureOrAPIKeyMiddleware(servicePublicKey, cfg.InternalAPIKey))
	internal.HandleFunc("/validate", authHandler.ValidateTokenHandler()).Methods("POST")
	internal.HandleFunc("/user/{id}", authHandler.GetUserHandler()).Methods("GET")
	internal.HandleFunc("/registrar-conductor", authHandler.RegistrarConductorHandler()).Methods("POST")
	internal.HandleFunc("/registrar-admin-publico", authHandler.RegistrarAdminPublicoHandler()).Methods("POST")  // ← NUEVA

	// Health check
	r.HandleFunc("/auth/health", healthHandler()).Methods("GET", "HEAD")

	// ── CORS ───────────────────────────────────────────────────────────────────
	c := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Signature", "X-Key-ID", "X-Internal-API-Key", "X-Requested-With"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	handler := c.Handler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Println("🚀 SafeRoute Auth Service — Independiente")
	log.Printf("🔒 Seguridad: JWT + Ed25519 Signatures + CORS + Rate Limiting")
	log.Printf("🌐 Iniciando en puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"auth-service","version":"1.0.0"}`))
	}
}