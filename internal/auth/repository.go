package auth

import (
	"database/sql"
	"log"
	"saferoute-auth/internal/security"
)

// Repository define las operaciones que el Auth Service necesita de la DB.
type Repository interface {
	FindByEmail(email string) (*UsuarioEntity, error)
	FindByID(id string) (*UsuarioEntity, error)
	Create(u *UsuarioEntity) (string, error)
	FindEmpresaByAdminID(adminID string) (*EmpresaInfo, error)
    CountConductoresByEmpresa(empresaID string) (int, error)
	CrearEmpresaPendiente(adminID string, nombreEmpresa string) error

}

type EmpresaInfo struct {
    ID                string
    AdminID           string
    PlanActual        string
    EstadoSuscripcion string
    MaxConductores    int
    ConductoresExtra  int
}

type authRepository struct {
	db *sql.DB
	encryptionKey []byte  // ← NUEVO

}

func NewRepositoryWithEncryption(db *sql.DB, encryptionKey []byte) Repository {
    return &authRepository{db: db, encryptionKey: encryptionKey}
}


func (r *authRepository) CrearEmpresaPendiente(adminID string, nombreEmpresa string) error {
    _, err := r.db.Exec(`
        INSERT INTO empresas (admin_id, nombre_empresa, plan_actual, estado_suscripcion, max_conductores)
        VALUES ($1, $2, 'basico', 'pendiente', 0)
        ON CONFLICT (admin_id) DO NOTHING`,
        adminID, nombreEmpresa,
    )
    return err
}

func (r *authRepository) FindEmpresaByAdminID(adminID string) (*EmpresaInfo, error) {
    e := &EmpresaInfo{}
    err := r.db.QueryRow(`
        SELECT id, admin_id, plan_actual, estado_suscripcion, 
               max_conductores, conductores_extra
        FROM empresas WHERE admin_id = $1`, adminID,
    ).Scan(&e.ID, &e.AdminID, &e.PlanActual, &e.EstadoSuscripcion,
        &e.MaxConductores, &e.ConductoresExtra)
    if err != nil {
        return nil, err
    }
    return e, nil
}

func (r *authRepository) CountConductoresByEmpresa(empresaID string) (int, error) {
    var total int
    err := r.db.QueryRow(`
        SELECT COUNT(*) FROM usuarios 
        WHERE empresa_id = $1 AND tipo = 'conductor'`, empresaID).Scan(&total)
    return total, err
}

// NewRepository crea un repositorio para el Auth Service.
func NewRepository(db *sql.DB) Repository {
	return &authRepository{db: db}
}

func (r *authRepository) FindByEmail(email string) (*UsuarioEntity, error) {
	u := &UsuarioEntity{}
	err := r.db.QueryRow(
		`SELECT id, email, password_hash, nombre, tipo, COALESCE(telefono, ''), created_at, updated_at
		 FROM usuarios WHERE email = $1`,
		email,
	).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Nombre,
		&u.Tipo, &u.Telefono, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *authRepository) FindByID(id string) (*UsuarioEntity, error) {
	u := &UsuarioEntity{}
	err := r.db.QueryRow(
		`SELECT id, email, password_hash, nombre, tipo, COALESCE(telefono, ''), created_at, updated_at
		 FROM usuarios WHERE id = $1`,
		id,
	).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Nombre,
		&u.Tipo, &u.Telefono, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *authRepository) Create(u *UsuarioEntity) (string, error) {
    log.Printf("[AUTH-REPO] Creando usuario - Email: %s, Teléfono: '%s'", u.Email, u.Telefono)

    // ✅ Cifrar teléfono si hay encryptionKey disponible
    if u.Telefono != "" && r.encryptionKey != nil {
        encrypted, err := security.Encrypt(u.Telefono, r.encryptionKey)
        if err != nil {
            log.Printf("[AUTH-REPO] Error cifrando teléfono: %v", err)
        } else {
            u.Telefono = encrypted
        }
    }

    var id string
    err := r.db.QueryRow(
        `INSERT INTO usuarios (email, password_hash, nombre, tipo, telefono, empresa_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        u.Email, u.PasswordHash, u.Nombre, u.Tipo, u.Telefono,
        nullableString(u.EmpresaID),
    ).Scan(&id)

    if err != nil {
        log.Printf("[AUTH-REPO] Error INSERT: %v", err)
        return "", err
    }

    log.Printf("[AUTH-REPO] Usuario creado - ID: %s", id)
    return id, nil
}

// compile-time check: asegura que authRepository implementa Repository
var _ Repository = (*authRepository)(nil)

func nullableString(s string) interface{} {
    if s == "" {
        return nil
    }
    return s
}