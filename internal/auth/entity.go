package auth

import (
	"log"
	"saferoute-auth/internal/security"
	"time"
)

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



func (u *UsuarioEntity) AfterLoad(key []byte) error {
    if u.Telefono == "" {
        return nil
    }
    decrypted, err := security.Decrypt(u.Telefono, key)
    if err != nil {
        // Teléfono en texto plano o corrupto - no fallar
        log.Printf("[AUTH] Teléfono no cifrado para usuario %s, se deja como está", u.ID)
        return nil
    }
    u.Telefono = decrypted
    return nil
}