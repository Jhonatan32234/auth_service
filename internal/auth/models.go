package auth

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Nombre   string `json:"nombre"`
	Tipo     string `json:"tipo"`
	Telefono string `json:"telefono"`
}

type AuthResponse struct {
	Token  string `json:"token"`
	Nombre string `json:"nombre"`
	Tipo   string `json:"tipo"`
	Email  string `json:"email,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

// ValidateTokenResponse es la respuesta del endpoint /auth/internal/validate
type ValidateTokenResponse struct {
	Valid  bool   `json:"valid"`
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Tipo   string `json:"tipo,omitempty"`
	Nombre string `json:"nombre,omitempty"`
	Error  string `json:"error,omitempty"`
}

// UserProfileResponse es la respuesta del endpoint /auth/internal/user/{id}
type UserProfileResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Nombre   string `json:"nombre"`
	Tipo     string `json:"tipo"`
	Telefono string `json:"telefono"`
}