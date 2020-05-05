package handler

import (
	"bsep/auth"
	"bsep/service"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"html/template"
	"net/http"
)

type LoginHandler struct {
	userService *service.UserService
	tpl *template.Template
}

func NewLoginHandler(us *service.UserService, tpl *template.Template) *LoginHandler {
	return &LoginHandler{userService: us,tpl: tpl}
}

type UserJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (lg *LoginHandler) SignUp(c echo.Context) error {
	return lg.tpl.ExecuteTemplate(c.Response().Writer,"register.gohtml",nil)
}

func (lg *LoginHandler) Register(c echo.Context) error {
	jsondata := UserJSON{}
	err := c.Bind(&jsondata)
	if err != nil || jsondata.Username == "" || jsondata.Password == "" {
		http.Error(c.Response().Writer,"Missing username or password", http.StatusBadRequest)
		return err
	}
	if lg.userService.HasUser(jsondata.Username){
		http.Error(c.Response().Writer,"Username already exists", http.StatusBadRequest)
		return err
	}

	user := lg.userService.DB.AddUser(jsondata.Username,jsondata.Password)
	jsontoken := auth.GetJSONToken(user)
	c.Response().Header().Set("Content-Type","application/json")
	//c.Response().Write([]byte(jsontoken))

	return c.JSON(http.StatusOK, jsontoken)
}

func(lg *LoginHandler)LoginHtml(c echo.Context)error{
	return lg.tpl.ExecuteTemplate(c.Response().Writer,"login.gohtml",nil)
}

func(lg *LoginHandler)Login(c echo.Context)error{
	jsondata := UserJSON{}
	err := c.Bind(&jsondata)
	if err != nil || jsondata.Username == "" || jsondata.Password == "" {
		http.Error(c.Response().Writer,"Missing username or password", http.StatusBadRequest)
		return err
	}
	user := lg.userService.DB.FindUser(jsondata.Username)
	if user.Username == "" {
		http.Error(c.Response().Writer,"username not found", http.StatusBadRequest)
		return  err
	}
	if !lg.userService.DB.CheckPassword(user.PasswordHash, jsondata.Password){
		http.Error(c.Response().Writer,"bad password", http.StatusBadRequest)
		return errors.New("try again")
	}

	jsontoken := auth.GetJSONToken(user)
	c.Response().Writer.Header().Set("Contet-Type","application/json")
	c.Response().Writer.Write([]byte(jsontoken))
	return nil
}


func(lg *LoginHandler)CheckUser(c echo.Context)error{
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	return c.String(http.StatusOK,"Welcome: " + username)
}
