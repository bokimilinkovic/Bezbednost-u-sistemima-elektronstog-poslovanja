package main

import (
	"bsep/handler"
	"bsep/middleware"
	"bsep/repository"
	"bsep/service"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"html/template"
	"log"
	"os"
	"strconv"
	"time"
)

var tpl *template.Template

func init(){
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"csrfField": func() (template.HTML,error){
			return "", errors.New("not defined yet")
		},
	}).ParseGlob("views/*.gohtml"))
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
	domain := os.Getenv("DOMAIN")
	sessionAuthKey := os.Getenv("SESSION_AUTH_KEY")
	sessionEncryptionKey := os.Getenv("SESSION_ENCRYPTION_KEY")


	store, err := repository.Open(config)
	if err != nil {
		panic(err)
	}
	defer store.Close()
	err = store.AutoMigrate()
	if err != nil {
		panic(err)
	}

	rawSessionAuthKey, err := base64.StdEncoding.DecodeString(sessionAuthKey)
	if err != nil {
		panic(err)
	}
	rawSessionEncryptionKey, err := base64.StdEncoding.DecodeString(sessionEncryptionKey)
	if err != nil {
		panic(err)
	}

	certificateService := &service.CertificateService{CertificateDB: store}
	loginService := &service.UserService{DB: store}
	certificateHandler := handler.NewCertificateHandler(certificateService, tpl,loginService)

	userLoader := middleware.UserLoader{UserService:loginService}

	//Logging and monitoring
	if !FileExists("logfile"){
		CreateFile("logfile")
	}
	f, err := os.OpenFile("logfile", os.O_RDWR | os.O_CREATE | os.O_APPEND, 066)
	if err != nil{
		log.Fatal("Error openning file: %v", err)
	}
	defer f.Close()


	logger := log.New(f, "INFO: ", log.Ldate | log.Ltime | log.Lshortfile)

	loginHandler := handler.NewLoginHandler(domain,loginService, tpl, logger)

	e := echo.New()
	e.Logger.SetOutput(f)
	e.Use(echomiddleware.LoggerWithConfig(echomiddleware.LoggerConfig{
		Output: f,
	}))
	fmt.Println("Server started")
	authkey, err := GenerateRandomString(32)
	if err != nil{
		panic(err)
	}
	fmt.Println(authkey)
	//key := make([]byte,32)
	//_, err = rand.Read(key)
	//if err != nil{
	//	panic(err)
	//}
	//fmt.Println("KEY : " ,string(key))
	CSRF := csrf.Protect([]byte(authkey))

	e.Use(echo.WrapMiddleware(CSRF))
	e.Use(session.Middleware(sessions.NewCookieStore(rawSessionAuthKey,rawSessionEncryptionKey)))
	//e.Use(echomiddleware.CSRFWithConfig(echomiddleware.CSRFConfig{
	//	TokenLookup: "form:csrf",
	//}))
	//csrf := csrf2.Protect([]byte("32-byte-long-auth-key"))
	//
	userApi := e.Group("/api/user")
	userApi.GET("/signup", loginHandler.SignUp)
	userApi.POST("/register", loginHandler.Register)
	userApi.GET("/login", loginHandler.LoginHtml)
	userApi.POST("/login", loginHandler.Login)
	userApi.GET("/logout",loginHandler.Logout)
	userApi.GET("/private", loginHandler.CheckUser, userLoader.Do)
	userApi.GET("/readlog", loginHandler.ReadLog, userLoader.Do)
	//e.GET("/login", loginHandler.Login)
	//e.POST("/loging",loginHandler.Logging)
	e.GET("/createnew", certificateHandler.CreateNew, userLoader.Do)
	e.POST("/create", certificateHandler.Create, userLoader.Do)
	e.GET("/readAll", certificateHandler.ReadAllInfo)
	e.GET("/home", certificateHandler.Home)
	e.GET("/certificate/:number", certificateHandler.Check)
	e.POST("/revoke/:number", certificateHandler.Revoke, userLoader.Do)
	e.POST("/download/:number", certificateHandler.Download)

	//e.Use(echomiddleware.CSRFWithConfig(echomiddleware.CSRFConfig{
	//	TokenLookup: "header:X-XSRF-TOKEN",
	//}))
	//e.Server.Addr = ":8080"
	logger.Printf("TODAY IS : %v", time.Now())
	e.Logger.Fatal(e.StartTLS(":1323","certificate/cert.pem","certificate/key.pem"))


}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func FileExists(filename string)bool{
	if _, err := os.Stat(filename); err != nil{
		if os.IsNotExist(err){
			return false
		}
	}
	return true
}

func CreateFile(name string)error{
	fo, err := os.Create(name)
	if err != nil{
		return err
	}
	defer func(){
		fo.Close()
	}()
	return nil
}
