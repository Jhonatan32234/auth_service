package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Handler struct {
	authSvc   *AuthService
	jwtSecret string
}

func NewHandler(authSvc *AuthService, jwtSecret string) *Handler {
	return &Handler{
		authSvc:   authSvc,
		jwtSecret: jwtSecret,
	}
}

func (h *Handler) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "datos de entrada inválidos")
			return
		}

		if err := ValidateLogin(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		result, err := h.authSvc.Login(req)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (h *Handler) RegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "datos de entrada inválidos")
			return
		}

		if err := ValidateRegister(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		log.Printf("[REGISTER] Datos recibidos - Email: %s, Nombre: %s, Teléfono: '%s', Tipo: %s",
			req.Email, req.Nombre, req.Telefono, req.Tipo)

		result, err := h.authSvc.Register(req)
		if err != nil {
			log.Printf("[REGISTER] Error: %v", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		log.Printf("[REGISTER] Usuario creado: %s, Teléfono guardado: '%s'",
			result.Email, req.Telefono)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(result)
	}
}

// saferoute-auth/internal/auth/handler.go

// RegistrarAdminPublicoHandler - Crea admin + empresa pendiente
func (h *Handler) RegistrarAdminPublicoHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Email    string `json:"email"`
            Password string `json:"password"`
            Nombre   string `json:"nombre"`
            Telefono string `json:"telefono"`
        }

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeError(w, http.StatusBadRequest, "datos inválidos")
            return
        }

        // Validaciones
        if req.Email == "" || req.Password == "" || req.Nombre == "" {
            writeError(w, http.StatusBadRequest, "email, password y nombre son requeridos")
            return
        }
        if len(req.Password) < 6 {
            writeError(w, http.StatusBadRequest, "la contraseña debe tener al menos 6 caracteres")
            return
        }

        log.Printf("[REGISTER-ADMIN-PUBLICO] Email: %s, Nombre: %s", req.Email, req.Nombre)

        result, err := h.authSvc.RegisterAdminPublico(req.Email, req.Password, req.Nombre, req.Telefono)
        if err != nil {
            log.Printf("[REGISTER-ADMIN-PUBLICO] Error: %v", err)
            writeError(w, http.StatusConflict, err.Error())
            return
        }

        log.Printf("[REGISTER-ADMIN-PUBLICO] Admin creado: %s (ID: %s)", result.Email, result.UserID)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(result)
    }
}
// ─── FIN NUEVO ───────────────────────────────────────────────────────────

func (h *Handler) ValidateTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "datos inválidos")
			return
		}

		if req.Token == "" {
			writeError(w, http.StatusBadRequest, "token es requerido")
			return
		}

		result, err := h.authSvc.ValidateToken(req.Token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(ValidateTokenResponse{
				Valid: false,
				Error: err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ValidateTokenResponse{
			Valid:  true,
			UserID: result["user_id"].(string),
			Email:  result["email"].(string),
			Tipo:   result["tipo"].(string),
			Nombre: func() string {
				if n, ok := result["nombre"].(string); ok {
					return n
				}
				return ""
			}(),
		})
	}
}

func (h *Handler) GetUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		if userID == "" {
			writeError(w, http.StatusBadRequest, "id de usuario requerido")
			return
		}

		user, err := h.authSvc.GetUserByID(userID)
		if err != nil {
			writeError(w, http.StatusNotFound, "usuario no encontrado")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UserProfileResponse{
			ID:       user.ID,
			Email:    user.Email,
			Nombre:   user.Nombre,
			Tipo:     user.Tipo,
			Telefono: user.Telefono,
		})
	}
}

func (h *Handler) RegistrarConductorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Nombre   string `json:"nombre"`
			Telefono string `json:"telefono"`
			AdminID  string `json:"admin_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "datos inválidos")
			return
		}

		// ✅ ZERO TRUST: Validar límites del plan
		if req.AdminID != "" {
			limite, err := h.authSvc.VerificarLimiteConductores(req.AdminID)
			if err != nil {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			log.Printf("[ZERO-TRUST] Admin %s: límite verificado (%d conductores permitidos)", 
				req.AdminID, limite)
		}

		if req.Email == "" || req.Password == "" || req.Nombre == "" {
			writeError(w, http.StatusBadRequest, "email, password y nombre son requeridos")
			return
		}

		id, err := h.authSvc.RegisterConductor(
			req.Email, 
			req.Password, 
			req.Nombre, 
			req.Telefono,
			req.AdminID,
		)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id":     id,
			"status": "conductor registrado",
			"email":  req.Email,
		})
	}
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
		"code":  code,
	})
}