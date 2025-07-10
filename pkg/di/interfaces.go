package di

import (
	"github.com/DeryuginVladislav/auth-service/internal/models"
)

type ISessionRepository interface {
	GetSession(id string) (*models.Session, error)
	CreateSession(s *models.Session) error
	DeactiveSession(id string) error
	DeactiveUserSessions(guid string) error
}
