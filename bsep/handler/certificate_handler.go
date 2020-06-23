package handler

import (
	"bsep/handler/dto"
	"bsep/model"
	"bsep/service"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/gorilla/csrf"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	validator2 "gopkg.in/validator.v2"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type CertificateHandler struct {
	certificateService *service.CertificateService
	userService *service.UserService
	tpl *template.Template
	logger *log.Logger

}

func NewCertificateHandler(cs *service.CertificateService, tpl *template.Template, userService *service.UserService, logger *log.Logger) *CertificateHandler {
	return &CertificateHandler{certificateService: cs, tpl:tpl, userService: userService, logger: logger}
}

const maxUploadSize = 2 * 1024 * 1024 // 2 mb
const uploadPath = "./keys"

func (ch *CertificateHandler) CreateNew(c echo.Context) error {
	//Get use and check permission
	user, ok := c.Get("user").(*model.User)
	if !ok{
		return errors.New("Error getting user from context")
	}
	ch.logger.Println("USER : " + user.Username)
	isAuthorize := false
	for _, role := range user.Roles{
		for _, permi := range role.Permissions{
			if permi.Name == model.CreateCertificateAuth{
				isAuthorize = true
				break
			}
		}
	}
	if !isAuthorize{
		ch.logger.Println("NOT AUTHORIZED TO DO THAT : ")
		return echo.NewHTTPError(http.StatusForbidden,"You are not authorized to do that")
	}

	csrfField := csrf.TemplateField(c.Request())
	tpl := ch.tpl.Funcs(template.FuncMap{
		"csrfField": func()template.HTML{
			return csrfField
		},
	})
	fmt.Println(csrfField)

	infos := []string{}
	certs := ch.certificateService.ValidToCA()
	for _, c := range certs {
		majorInfo := fmt.Sprintf("%s, %s, %s, %s, %s, %s, %s", c.Subject.Organization[0], c.Subject.StreetAddress[0], c.Subject.Locality[0], c.Subject.Province[0], c.Subject.Country[0], c.Subject.SerialNumber, c.Subject.PostalCode[0])
		fmt.Println(majorInfo)
		infos = append(infos, majorInfo)
	}
	data := map[string]interface{}{
		//csrf.TemplateTag: csrftoken,
		"infos": infos,
	}

	return tpl.ExecuteTemplate(c.Response().Writer,"create.gohtml",data)
}

func (ch *CertificateHandler) Create(c echo.Context) error {
	user, ok := c.Get("user").(*model.User)
	if !ok{
		return errors.New("Error getting user from context")
	}
	fmt.Println(user.Username + " " + user.Roles[0].Name + " " + user.Roles[0].Permissions[0].Name)
	isAuthorize := false
	for _, role := range user.Roles{
		for _, permi := range role.Permissions{
			if permi.Name == model.CreateCertificateAuth{
				isAuthorize = true
				break
			}
		}
	}
	if !isAuthorize{
		ch.logger.Println("NOT AUTHORIZED TO DO THAT : ")
		return echo.NewHTTPError(http.StatusForbidden,"You are not authorized to do that")
	}
	validator := validator2.NewValidator()
	var request dto.CertificateRequest
	err := c.Bind(&request)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	err = validator.Validate(request)
	if err != nil{
		http.Error(c.Response().Writer,err.Error(),http.StatusBadRequest)
		return err
	}
	err = ch.certificateService.CreateCertificate(&request)
	if err != nil {
		return err
	}

	return c.HTML(http.StatusOK, `<body><h3>Successfully created...</h3><br><a href="/home">Go to home page</a></body>`)
}

func (ch *CertificateHandler) Home(c echo.Context) error {
	sess,_ := session.Get("session",c)
	userID ,ok := sess.Values["userID"].(int)
	var user *model.User
	if !ok {
		user = nil
	}
	if ok{
		user, _= ch.userService.DB.FindUserByID(userID)
	}
	fmt.Println("USER:" , user, " ID : ", userID)
	type UserInfo struct{
		User *model.User
		Admin bool
	}
	type Response struct{
		UserInfo *UserInfo
		Certificats []dto.CertificateResponse
	}
	certificates, err := ch.certificateService.ReadKeyStoreAllInfo()
	if err != nil {
		return err
	}
	//if len(certificates) == 0 {
	//	return ch.tpl.ExecuteTemplate(c.Response().Writer,"home.gohtml", []dto.CertificateResponse{})
	//}
	responses := []dto.CertificateResponse{}
	for _, c := range certificates {
		revoked := ch.certificateService.IsRevoked(c)
		valid := ch.certificateService.ValidCertificate(c)
		responses = append(responses, toCertificateResponse(c, revoked, valid))
	}
	admin := false
	if user != nil{
		for _, role := range user.Roles{
			if role.Name == "Admin"{
				admin = true
				break
			}
		}
	}
	userinfo := UserInfo{User:user, Admin:admin}
	response := Response{
		UserInfo: &userinfo,
		Certificats: responses,
	}
	fmt.Println(userinfo.User)
	csrfField := csrf.TemplateField(c.Request())
	tpl := ch.tpl.Funcs(template.FuncMap{
		"csrfField": func()template.HTML{
			return csrfField
		},
	})
	fmt.Println(csrfField)
	return tpl.ExecuteTemplate(c.Response().Writer,"home.gohtml",response)
}

func (ch *CertificateHandler) ReadAllInfo(c echo.Context) error {
	certs, err := ch.certificateService.ReadKeyStoreAllInfo()
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, certs)
}

func (ch *CertificateHandler) Check(c echo.Context) error {
	//I need to splitr url path : /revoke/2313
	parts := strings.Split(c.Request().URL.Path, "/")
	serialNumber := parts[2]
	num, err := strconv.Atoi(serialNumber)
	if err != nil {
		panic(err)
	}
	cert := ch.certificateService.FindCertificatBySerialNumber(num)
	if cert == nil{
		return c.HTML(http.StatusNotFound,`<body>Certificate with that serial number is not found</body>`)
	}
	isRevoked := ch.certificateService.IsRevoked(cert)
	if isRevoked{
		return c.HTML(http.StatusOK,`<body>Certificate with that serial number already revoked</body>`)
	}

	return c.HTML(http.StatusOK, `<body><h4>Certificate: ` + cert.Subject.Organization[0] + `</h4> is not revoked..</body>`)
}

func (ch *CertificateHandler) Revoke(c echo.Context) error {
	//I need to splitr url path : /revoke/2313
	user, ok := c.Get("user").(*model.User)
	if !ok{
		return echo.NewHTTPError(http.StatusForbidden,"You are not authorized to do that")
	}
	isAuthorize := false
	for _, role := range user.Roles{
		for _, permi := range role.Permissions{
			if permi.Name == model.RevokeCertificateAuth{
				isAuthorize = true
				break
			}
		}
	}
	if !isAuthorize{
		ch.logger.Println("NOT AUTHORIZED TO DO THAT : ")
		return echo.NewHTTPError(http.StatusForbidden,"You are not authorized to do that")
	}
	parts := strings.Split(c.Request().URL.Path, "/")
	serialNumber := parts[2]
	fmt.Println("**")
	err := ch.certificateService.RevokeCertificate(serialNumber)
	if err != nil {
		fmt.Println("here we got the error : ", err.Error())
		return err
	}
	//csrfField := csrf.TemplateField(c.Request())
	//fmt.Println("****" , csrfField)
	return c.HTML(http.StatusOK, `<body><h3>Successfully revoked...</h3><br><a href="/home">Go to home page</a></body>`)
}

func (ch *CertificateHandler) Download(c echo.Context) error {
	parts := strings.Split(c.Request().URL.Path, "/")
	Filename := parts[2]
	if Filename == "" {
		//Get not set, send a 400 bad request
		return errors.New("Get 'file' not specified in url.")
	}
	fmt.Println("Client requests: " + Filename)
	serialNumber := strings.Split(Filename, "-")[0]
	fmt.Println("Serial Number : ", serialNumber)
	Openfile, err := os.Open(fmt.Sprintf("keys/%s/certpem%s.pem", Filename, serialNumber))
	defer Openfile.Close() //Close after function return
	if err != nil {
		return err
	}

	FileHeader := make([]byte, 512)
	//Copy the headers into the FileHeader buffer
	Openfile.Read(FileHeader)
	//Get content type of file
	FileContentType := http.DetectContentType(FileHeader)

	//Get the file size
	FileStat, _ := Openfile.Stat()                     //Get info from file
	FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

	//Send the headers
	c.Response().Writer.Header().Set("Content-Disposition", "attachment; filename="+Filename)
	c.Response().Writer.Header().Set("Content-Type", FileContentType)
	c.Response().Writer.Header().Set("Content-Length", FileSize)

	//Send the file
	//We read 512 bytes from the file already, so we reset the offset back to 0
	Openfile.Seek(0, 0)
	io.Copy(c.Response().Writer, Openfile) //'Copy' the file to the client

	return nil
}

func toCertificateResponse(c *x509.Certificate, revoked, valid bool) dto.CertificateResponse {
	issuer := fmt.Sprintf("%s:%s", c.Issuer.Country[0], c.Issuer.Organization[0])
	validFromTo := fmt.Sprintf("%s - %s",c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	return dto.CertificateResponse{
		Country:      c.Subject.Country[0],
		Organization: c.Subject.Organization[0],
		CommonName:   c.Subject.CommonName,
		Address:      c.Subject.StreetAddress[0],
		Email:        c.EmailAddresses[0],
		SerialNumber: c.SerialNumber.String(),
		Issuer:       issuer,
		Revoked:      revoked,
		Valid:		  valid,
		ValidFromTo:  validFromTo,
	}
}
