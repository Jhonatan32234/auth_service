package auth

import (
	"fmt"
	"strings"
)

func ValidateLogin(req *LoginRequest) error {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" {
		return fmt.Errorf("el campo 'email' es requerido")
	}
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("el campo 'email' no tiene un formato válido")
	}
	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("el campo 'password' es requerido")
	}
	return nil
}

func ValidateRegister(req *RegisterRequest) error {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Nombre = strings.TrimSpace(req.Nombre)
	req.Telefono = strings.TrimSpace(req.Telefono)

	if req.Email == "" {
		return fmt.Errorf("el campo 'email' es requerido")
	}
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("el campo 'email' no tiene un formato válido")
	}
	if len(req.Password) < 6 {
		return fmt.Errorf("la contraseña debe tener al menos 6 caracteres")
	}
	if req.Nombre == "" {
		return fmt.Errorf("el campo 'nombre' es requerido")
	}
	if req.Tipo == "" {
		req.Tipo = "conductor"
	}
	if req.Tipo != "conductor" {
		return fmt.Errorf("el campo 'tipo' solo puede ser 'conductor' para el registro público")
	}
	return nil
}