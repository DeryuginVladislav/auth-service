package models

import "time"

type Session struct {
	ID          string
	UserGUID    string
	RefreshHash string
	UserAgent   string
	IP          string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	IsActive    bool
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}
type UserResponse struct {
	Guid string `json:"guid"`
}
