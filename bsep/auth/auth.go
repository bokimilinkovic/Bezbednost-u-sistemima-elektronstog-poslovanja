package auth

import (
	"bsep/model"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var singingKey = []byte("Some-secret-key")

//GetToken create a jwt token with user claims
func GetToken(user *model.User)string{
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	signedToken, _ := token.SignedString(singingKey)
	fmt.Println("TOKEN : " , signedToken)
	return signedToken
}

//GetJsonToken create a JSON token string
func GetJSONToken(user *model.User)string{
	token := GetToken(user)
	jsontoken := "{\"id_token\": \"" + token + "\"}"
	return jsontoken
}