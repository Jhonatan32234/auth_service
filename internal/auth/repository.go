package auth

import (
	"database/sql"
	"log"
)

// Repository define las operaciones que el Auth Service necesita de la DB.
type Repository interface {
	FindByEmail(email string) (*UsuarioEntity, error)
	FindByID(id string) (*UsuarioEntity, error)
	Create(u *UsuarioEntity) (string, error)
}

type authRepository struct {
	db *sql.DB
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

	var id string
	err := r.db.QueryRow(
		`INSERT INTO usuarios (email, password_hash, nombre, tipo, telefono)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		u.Email, u.PasswordHash, u.Nombre, u.Tipo, u.Telefono,
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