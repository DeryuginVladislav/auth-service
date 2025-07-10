package internal

import (
	"database/sql"

	"github.com/DeryuginVladislav/auth-service/internal/models"
)

type SessionRepository struct {
	Database *sql.DB
}

func NewSessionReposytory(database *sql.DB) *SessionRepository {
	return &SessionRepository{
		Database: database,
	}
}

func (repo *SessionRepository) CreateSession(s *models.Session) error {
	_, err := repo.Database.Exec(
		`INSERT INTO sessions (id, user_guid, refresh_hash, user_agent, ip, expires_at, is_active)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID,
		s.UserGUID,
		s.RefreshHash,
		s.UserAgent,
		s.IP,
		s.ExpiresAt,
		s.IsActive,
	)
	return err
}

func (repo *SessionRepository) GetSession(id string) (*models.Session, error) {
	var s models.Session
	err := repo.Database.QueryRow(
		`SELECT id, user_guid, refresh_hash, user_agent, ip, created_at, expires_at, is_active
		FROM sessions
		WHERE id = $1`, id,
	).Scan(
		&s.ID,
		&s.UserGUID,
		&s.RefreshHash,
		&s.UserAgent,
		&s.IP,
		&s.CreatedAt,
		&s.ExpiresAt,
		&s.IsActive,
	)
	return &s, err
}

func (repo *SessionRepository) DeactiveSession(id string) error {
	_, err := repo.Database.Exec(
		`UPDATE sessions
		SET is_active = false
		WHERE id = $1`, id,
	)
	return err
}

func (repo *SessionRepository) DeactiveUserSessions(guid string) error {
	_, err := repo.Database.Exec(
		`UPDATE sessions
		SET is_active = false
		WHERE user_guid = $1`, guid,
	)
	return err
}
