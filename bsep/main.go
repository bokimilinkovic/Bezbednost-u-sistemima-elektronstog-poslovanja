package main

import (
	"bsep/handler"
	"bsep/middleware"
	"bsep/repository"
	"bsep/service"
	"fmt"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/joho/godotenv"
	"html/template"
	"os"
	"strconv"
)

var tpl *template.Template

func init(){
	tpl = template.Must(template.ParseGlob("views/*.gohtml"))
}

func main() {
	err := godotenv.Load()
	if err != nil{
		panic(err)
	}
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil{
		panic(err)
	}
	config := repository.PostgresConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     port,
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		Name:     os.Getenv("DB_NAME"),
	}

	store, err := repository.Open(config)
	if err != nil {
		panic(err)
	}
	defer store.Close()
	err = store.AutoMigrate()
	if err != nil {
		panic(err)
	}

	certificateService := &service.CertificateService{CertificateDB: store}
	certificateHandler := handler.NewCertificateHandler(certificateService, tpl)
	loginService := &service.UserService{DB: store}
	loginHandler := handler.NewLoginHandler(loginService, tpl)
	e := echo.New()
	e.Use(echomiddleware.Logger())
	fmt.Println("Server started")

	userApi := e.Group("/api/user")
	userApi.GET("/signup", loginHandler.SignUp)
	userApi.POST("/register", loginHandler.Register)
	userApi.GET("/login", loginHandler.LoginHtml)
	userApi.POST("/login", loginHandler.Login)

	userApi.GET("/private", loginHandler.CheckUser ,middleware.IsLoggedIn)
	//e.GET("/login", loginHandler.Login)
	//e.POST("/loging",loginHandler.Logging)
	e.GET("/createnew", certificateHandler.CreateNew)
	e.POST("/create", certificateHandler.Create)
	e.GET("/readAll", certificateHandler.ReadAllInfo)
	e.GET("/home", certificateHandler.Home)
	e.GET("/certificate/:number", certificateHandler.Check)
	e.POST("/revoke/:number", certificateHandler.Revoke)
	e.POST("/download/:number", certificateHandler.Download)
	e.Server.Addr = ":8080"
	e.Logger.Fatal(e.Start(":8080"))

}
