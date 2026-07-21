package auth

import "time"

// UsuarioEntity representa un usuario en el sistema.
// Esta es una versión independiente de la entidad user.UsuarioEntity del proyecto principal.
type UsuarioEntity struct {
    ID           string
    Email        string
    PasswordHash string
    Nombre       string
    Tipo         string
    Telefono     string
    EmpresaID    string 
    CreatedAt    time.Time
    UpdatedAt    time.Time
    UltimoAcceso *time.Time
}