package internal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/DeryuginVladislav/auth-service/configs"
	"github.com/DeryuginVladislav/auth-service/internal/models"
	"github.com/DeryuginVladislav/auth-service/pkg/di"
	"github.com/DeryuginVladislav/auth-service/pkg/jwt"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var ErrSessionExpired = errors.New("session expired")

type AuthService struct {
	SessionRepository di.ISessionRepository
	Config            *configs.Config
}

func NewAuthService(sessionRepository di.ISessionRepository, config *configs.Config) *AuthService {
	return &AuthService{
		SessionRepository: sessionRepository,
		Config:            config,
	}
}

func (s *AuthService) GenerateTokens(guid, userAgent, ip string) (*models.TokenResponse, error) {
	_, err := uuid.Parse(guid)
	if err != nil {
		return nil, err
	}

	sessionID := uuid.New().String()

	accessToken, err := jwt.NewJWT(s.Config.Auth.Secret).Create(guid, sessionID, s.Config.Auth.TTL)
	if err != nil {
		return nil, err
	}

	refreshBytes := make([]byte, 32)
	_, err = rand.Read(refreshBytes)
	if err != nil {
		return nil, err
	}
	refreshToken := base64.StdEncoding.EncodeToString(refreshBytes)

	refreshHash, err := bcrypt.GenerateFromPassword(refreshBytes, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	session := &models.Session{
		ID:          sessionID,
		UserGUID:    guid,
		RefreshHash: string(refreshHash),
		UserAgent:   userAgent,
		IP:          ip,
		ExpiresAt:   time.Now().Add(720 * time.Hour).UTC(),
		IsActive:    true,
	}
	err = s.SessionRepository.CreateSession(session)
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
func (s *AuthService) RefreshTokens(accessToken, refreshToken, userAgent, ip string) (*models.TokenResponse, error) {
	token, err := jwtv5.ParseWithClaims(accessToken, &jwt.CustomClaims{}, func(t *jwtv5.Token) (interface{}, error) {
		return []byte(s.Config.Auth.Secret), nil
	})
	if err != nil && !errors.Is(err, jwtv5.ErrTokenExpired) {
		return nil, err
	}
	claims, ok := token.Claims.(*jwt.CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	refreshBytes, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return nil, err
	}

	session, err := s.SessionRepository.GetSession(claims.SessionID)

	if err != nil || !session.IsActive {
		return nil, ErrSessionExpired
	}

	if session.ExpiresAt.Before(time.Now().UTC()) {
		s.SessionRepository.DeactiveSession(session.ID)
		return nil, ErrSessionExpired
	}

	if userAgent != session.UserAgent {
		s.SessionRepository.DeactiveUserSessions(claims.GUID)
		return nil, errors.New("invalid user agent")
	}

	err = bcrypt.CompareHashAndPassword([]byte(session.RefreshHash), refreshBytes)
	if err != nil {
		s.SessionRepository.DeactiveUserSessions(claims.GUID)
		return nil, errors.New("invalid refresh token")
	}

	if ip != session.IP {
		payload := map[string]string{
			"guid":   claims.GUID,
			"old_ip": session.IP,
			"new_ip": ip,
		}
		jsonData, _ := json.Marshal(payload)

		_, err = http.Post(s.Config.Auth.WebhookURL, "application/json", strings.NewReader(string(jsonData)))
		if err != nil {
			log.Printf("Webhook error: %v", err)
		}
	}

	err = s.SessionRepository.DeactiveSession(session.ID)
	if err != nil {
		return nil, err
	}
	return s.GenerateTokens(claims.GUID, userAgent, ip)
}

func (s *AuthService) GetUserGUID(accessToken string) (string, error) {
	claims, err := jwt.NewJWT(s.Config.Auth.Secret).Parse(accessToken)
	if err != nil {
		return "", err
	}
	session, err := s.SessionRepository.GetSession(claims.SessionID)
	if err != nil {
		return "", err
	}
	if !session.IsActive {
		return "", errors.New("session expired")
	}
	return claims.GUID, nil
}

func (s *AuthService) Logout(accessToken string) error {
	claims, err := jwt.NewJWT(s.Config.Auth.Secret).Parse(accessToken)
	if err != nil {
		return err
	}
	return s.SessionRepository.DeactiveSession(claims.SessionID)
}
