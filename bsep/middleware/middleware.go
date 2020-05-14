package middleware

import (
	"bsep/service"
	"errors"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
)

var IsLoggedIn = middleware.JWTWithConfig(middleware.JWTConfig{
	SigningKey: []byte("Some-secret-key"),
})

type UserLoader struct{
	UserService *service.UserService
}

func(ul *UserLoader)Do(next echo.HandlerFunc) echo.HandlerFunc{
	return func(c echo.Context)error{
		sess,err := session.Get("session",c)
		if err != nil {
			return err
		}
		userID ,ok := sess.Values["userID"].(int)
		if !ok {
			return errors.New("no value for wanted key - userID")
		}
		user, err := ul.UserService.DB.FindUserByID(userID)
		if err != nil{
			return echo.NewHTTPError(http.StatusBadRequest,"cannot find user with given Id")
		}
		c.Set("user",user)
		return next(c)
	}
}