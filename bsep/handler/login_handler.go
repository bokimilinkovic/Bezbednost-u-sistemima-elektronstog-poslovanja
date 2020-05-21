package handler

import (
	"bsep/model"
	"bsep/service"
	"errors"
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"gopkg.in/validator.v2"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
)

type LoginHandler struct {
	domain string
	userService *service.UserService
	tpl *template.Template
	logger *log.Logger
}

func NewLoginHandler(domain string, us *service.UserService, tpl *template.Template, logger *log.Logger) *LoginHandler {
	return &LoginHandler{domain: domain, userService: us,tpl: tpl, logger: logger}
}

type UserJSON struct {
	Username string `json:"username"`
	Password string `json:"password" validate:"min=6, regexp=^[a-zA-Z0-9_!@#$_%^&*.?()-=+]*$"`
	Token    string  `json:"gorilla.csrf.Token"`
}

func (lg *LoginHandler) SignUp(c echo.Context) error {
	csrfField := csrf.TemplateField(c.Request())
	tpl := lg.tpl.Funcs(template.FuncMap{
		"csrfField": func()template.HTML{
			return csrfField
		},
	})
	return tpl.ExecuteTemplate(c.Response().Writer,"register.gohtml",nil)
}

func (lg *LoginHandler) Register(c echo.Context) error {
	var validate = validator.NewValidator()
	jsondata := UserJSON{}
	err := c.Bind(&jsondata)
	if err != nil || jsondata.Username == "" || jsondata.Password == "" {
		http.Error(c.Response().Writer,"Missing username or password", http.StatusBadRequest)
		return err
	}
	errs := validate.Validate(jsondata)
	if errs != nil {
		http.Error(c.Response().Writer,errs.Error(),http.StatusBadRequest)
		return errs
	}
	if lg.userService.HasUser(jsondata.Username){
		http.Error(c.Response().Writer,"Username already exists", http.StatusBadRequest)
		return err
	}

	user := lg.userService.DB.AddUser(jsondata.Username,jsondata.Password)
	fmt.Println(user)
	lg.logger.Println("NEW USER REGISTERED: ",user.Username)
	//jsontoken := auth.GetJSONToken(user)
	//c.Response().Header().Set("Content-Type","application/json")
	//c.Response().Write([]byte(jsontoken))

	return c.HTML(http.StatusOK,`<h3>Successfully registed... go to <a href="/api/user/login">LOGIN PAGE</a></h3>   `)
}

func(lg *LoginHandler)LoginHtml(c echo.Context)error{
	csrfField := csrf.TemplateField(c.Request())
	tpl := lg.tpl.Funcs(template.FuncMap{
		"csrfField": func()template.HTML{
			return csrfField
		},
	})
	fmt.Println(csrfField)
	//data := map[string]interface{}{
	//	csrf.TemplateTag: csrftoken,
	//}
	return tpl.ExecuteTemplate(c.Response().Writer,"login.gohtml",nil)
}

func(lg *LoginHandler)Login(c echo.Context)error {
	sess, err := session.Get("session", c)
	if err != nil {
		return err
	}
	sess.Options = &sessions.Options{
		Domain:   lg.domain,
		Path:     "/",
		MaxAge:   3600 * 8,
		HttpOnly: true,
	}

	jsondata := UserJSON{}
	err = c.Bind(&jsondata)
	if err != nil || jsondata.Username == "" || jsondata.Password == "" {
		http.Error(c.Response().Writer, "Missing username or password", http.StatusBadRequest)
		return err
	}
	fmt.Println("TOKEN JE: ", jsondata.Token)
	user := lg.userService.DB.FindUser(jsondata.Username)
	if user.Username == "" {
		http.Error(c.Response().Writer, "username not found", http.StatusBadRequest)
		return err
	}
	if !lg.userService.DB.CheckPassword(user.PasswordHash, jsondata.Password) {
		http.Error(c.Response().Writer, "bad password", http.StatusBadRequest)
		return errors.New("try again")
	}
	sess.Values["userID"] = user.ID
	sess.Values["username"] = user.Username
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}
	lg.logger.Println("USER LOGGED IN: ",user.Username)

	return c.Redirect(302,"/home")
}
func(lg *LoginHandler)Logout(c echo.Context)error{
	sess, err := session.Get("session", c)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	sess.Values["userID"] = -1
	sess.Values["username"] = ""
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		fmt.Println(err.Error())
		return err


	}
	lg.logger.Println("USER LOGGED OUT: ")

	return c.Redirect(http.StatusFound, "/home")
}


func(lg *LoginHandler)CheckUser(c echo.Context)error{
	user, ok := c.Get("user").(*model.User)
	if !ok{
		return echo.NewHTTPError(http.StatusInternalServerError,"error retrieving user from context")
	}

	return c.String(http.StatusOK,"Welcome: " + user.Username)
}

func(lg *LoginHandler)ReadLog(c echo.Context)error{
	user, ok := c.Get("user").(*model.User)
	if !ok{
		return echo.NewHTTPError(http.StatusInternalServerError,"error retrieving user from context")
	}
	fmt.Println(user.Username)
	e := casbin.NewEnforcer("acl/model.conf","acl/pattern_policy.csv")
	sub := user.Username
	obj := "logfile"
	act := "read"
	if res := e.Enforce(sub,obj,act); res{
		data, err := ioutil.ReadFile("logfile")
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		fmt.Fprint(c.Response().Writer,string(data))
		return nil
	}
	return errors.New("Not aloowed")

}
