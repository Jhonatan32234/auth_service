package auth

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	usuarioRepo   Repository
	encryptionKey []byte
	jwtSecret     string
}

func NewAuthService(repo Repository, encryptionKey []byte, jwtSecret string) *AuthService {
	return &AuthService{
		usuarioRepo:   repo,
		encryptionKey: encryptionKey,
		jwtSecret:     jwtSecret,
	}
}

func (s *AuthService) Login(req LoginRequest) (AuthResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	usuario, err := s.usuarioRepo.FindByEmail(email)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("credenciales inválidas")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(usuario.PasswordHash), []byte(req.Password)); err != nil {
		return AuthResponse{}, fmt.Errorf("credenciales inválidas")
	}

	token, err := s.generateJWT(usuario.ID, usuario.Email, usuario.Tipo, usuario.Nombre)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error generando token")
	}

	return AuthResponse{
		Token:  token,
		Nombre: usuario.Nombre,
		Tipo:   usuario.Tipo,
		Email:  usuario.Email,
		UserID: usuario.ID,
	}, nil
}

func (s *AuthService) Register(req RegisterRequest) (AuthResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	nombre := strings.TrimSpace(req.Nombre)
	telefono := strings.TrimSpace(req.Telefono)

	if email == "" || req.Password == "" || nombre == "" {
		return AuthResponse{}, fmt.Errorf("email, password y nombre son requeridos")
	}

	existente, _ := s.usuarioRepo.FindByEmail(email)
	if existente != nil {
		return AuthResponse{}, fmt.Errorf("el email ya está registrado")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error procesando contraseña")
	}

	tipo := "conductor"
	if req.Tipo != "" && req.Tipo != "conductor" {
		tipo = req.Tipo
	}

	log.Printf("[AUTH] Registrando usuario - Email: %s, Teléfono: '%s'", email, telefono)

	entity := &UsuarioEntity{
		Email:        email,
		PasswordHash: string(hashedPassword),
		Nombre:       nombre,
		Tipo:         tipo,
		Telefono:     telefono,
	}

	userID, err := s.usuarioRepo.Create(entity)
	if err != nil {
		log.Printf("[AUTH] Error creando usuario: %v", err)
		return AuthResponse{}, fmt.Errorf("error al crear usuario")
	}

	log.Printf("[AUTH] Usuario creado - ID: %s", userID)

	token, err := s.generateJWT(userID, email, tipo, nombre)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error generando token")
	}

	return AuthResponse{
		Token:  token,
		Nombre: nombre,
		Tipo:   tipo,
		Email:  email,
		UserID: userID,
	}, nil
}

func (s *AuthService) ValidateToken(tokenString string) (map[string]interface{}, error) {
	claims, err := s.parseJWT(tokenString)
	if err != nil {
		return nil, err
	}

	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("user_id no encontrado en el token")
	}

	return map[string]interface{}{
		"user_id": userID,
		"email":   claims["email"],
		"tipo":    claims["tipo"],
		"nombre":  claims["nombre"],
	}, nil
}

func (s *AuthService) GetUserByID(id string) (*UsuarioEntity, error) {
	return s.usuarioRepo.FindByID(id)
}

func (s *AuthService) RegisterConductor(email, password, nombre, telefono string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	nombre = strings.TrimSpace(nombre)
	telefono = strings.TrimSpace(telefono)

	if email == "" || password == "" || nombre == "" {
		return "", fmt.Errorf("email, password y nombre requeridos")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("error procesando contraseña")
	}

	u := &UsuarioEntity{
		Email:        email,
		PasswordHash: string(hashedPassword),
		Nombre:       nombre,
		Tipo:         "conductor",
		Telefono:     telefono,
	}

	id, err := s.usuarioRepo.Create(u)
	if err != nil {
		return "", fmt.Errorf("el email ya está registrado")
	}
	return id, nil
}

func (s *AuthService) generateJWT(userID, email, tipo, nombre string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"tipo":    tipo,
		"nombre":  nombre,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("error firmando token: %w", err)
	}

	return tokenString, nil
}

func (s *AuthService) parseJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("token inválido")
}