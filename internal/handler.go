package internal

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/DeryuginVladislav/auth-service/internal/models"
	"github.com/DeryuginVladislav/auth-service/pkg/middleware"
	"github.com/DeryuginVladislav/auth-service/pkg/res"
)

type AuthHandler struct {
	*AuthService
}

func NewAuthHandler(router *http.ServeMux, service *AuthService) {
	handler := &AuthHandler{
		AuthService: service,
	}
	router.HandleFunc("GET /login", handler.Login())
	router.Handle("POST /refresh", middleware.IsAuthed(handler.Refresh()))
	router.Handle("GET /user", middleware.IsAuthed(handler.User()))
	router.Handle("POST /logout", middleware.IsAuthed(handler.Logout()))

}

// Login godoc
// @Summary      Авторизация пользователя
// @Description  Получение access и refresh токенов по guid пользователя
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        guid  query     string  true  "GUID пользователя"
// @Success      201   {object}  models.TokenResponse "Успешный ответ" example({"access_token": "eyJhbGciOi...", "refresh_token": "dGhpc2lzYXJlZnJlc2h0b2tlbg=="})
// @Failure      400   {string}  string  "guid is required"
// @Failure      500   {string}  string  "internal error"
// @Router       /login [get]
// @Example      request {"guid": "550e8400-e29b-41d4-a716-446655440000"}
// @Example      curl -X GET "http://localhost:8080/login?guid=1234"
func (h *AuthHandler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get("guid")
		if guid == "" {
			http.Error(w, "guid is required", http.StatusBadRequest)
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)

		tokens, err := h.AuthService.GenerateTokens(guid, r.Header.Get("User-Agent"), ip)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res.MakeJson(w, tokens, http.StatusCreated)
	}
}

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Введите токен в формате: Bearer <access_token>
// Refresh godoc
// @Summary      Обновление токенов
// @Description  Получение новых access и refresh токенов по refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      models.RefreshTokenRequest  true  "Refresh token request"
// @Success      201   {object}  models.TokenResponse "Успешный ответ" example({"access_token": "eyJhbGciOi...", "refresh_token": "dGhpc2lzYXJlZnJlc2h0b2tlbg=="})
// @Failure      400   {string}  string  "refresh token is required"
// @Failure      500   {string}  string  "internal error"
// @Router       /refresh [post]
// @Example      request {"refresh_token": "dGhpc2lzYXJlZnJlc2h0b2tlbg=="}
// @Example      curl -X POST "http://localhost:8080/refresh" -d '{"refresh_token":"..."}' -H "Content-Type: application/json"
// @Security BearerAuth
func (h *AuthHandler) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body models.RefreshTokenRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "refresh token is required", http.StatusBadRequest)
			return
		}

		accessToken := r.Context().Value(middleware.ContextTokenKey).(string)

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		tokens, err := h.AuthService.RefreshTokens(accessToken, body.RefreshToken, r.Header.Get("User-Agent"), ip)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res.MakeJson(w, tokens, http.StatusCreated)
	}
}

// User godoc
// @Summary      Получение информации о пользователе
// @Description  Получение GUID пользователя по access token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200   {object}  models.UserResponse "Успешный ответ" example({"guid": "550e8400-e29b-41d4-a716-446655440000"})
// @Failure      500   {string}  string  "internal error"
// @Router       /user [get]
// @Example      curl -X GET "http://localhost:8080/user" -H "Authorization: Bearer <access_token>"
// @Security BearerAuth
func (h *AuthHandler) User() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Context().Value(middleware.ContextTokenKey).(string)
		guid, err := h.AuthService.GetUserGUID(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res.MakeJson(w, models.UserResponse{Guid: guid}, 200)
	}
}

// Logout godoc
// @Summary      Выход пользователя
// @Description  Деактивация сессии пользователя по access token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200   {string}  string  "ok" example("ok")
// @Failure      500   {string}  string  "internal error"
// @Router       /logout [post]
// @Example      curl -X POST "http://localhost:8080/logout" -H "Authorization: Bearer <access_token>"
// @Security BearerAuth
func (h *AuthHandler) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Context().Value(middleware.ContextTokenKey).(string)
		err := h.AuthService.Logout(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		res.MakeJson(w, nil, 200)
	}
}
