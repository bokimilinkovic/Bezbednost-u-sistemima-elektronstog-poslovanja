package main

import (
	"bsep/model"
	"bsep/repository"
	"golang.org/x/crypto/bcrypt"
)

func main(){
	store, err := connect()
	if err != nil{
		panic(err)
	}
	defer store.Close()
	store.DB().DropTableIfExists(&model.Role{}, &model.User{}, &model.Permission{})
	store.DB().AutoMigrate(&model.User{}, &model.Role{}, &model.Permission{})

	role := &model.Role{Name:"Admin"}
	permission1 := &model.Permission{Name:"Create-Certificate"}
	permission2 := &model.Permission{Name:"Revoke-Certificate"}
	role.Permissions = append(role.Permissions, permission1,permission2)
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"+"admin"), bcrypt.DefaultCost)
	if err != nil {
		panic("Permissions: bcrypt password hasnig unsuccessful")
	}
	pass := string(hash)
	user := model.User{Username:"admin",PasswordHash:pass, Active:true, Salt:"admin"}
	user.Roles = append(user.Roles,role)
	err = store.DB().Save(&user).Error
	if err != nil{
		panic(err)
	}
	//
	//role2 := &model.Role{Name:"Kupac"}
	//store.DB().Model(&user).Association("Roles").Append([]*model.Role{role2})
	//user3 := &model.User{}
	//store.DB().Preload("Roles.Permissions").First(&user3)
	//fmt.Println("User: ", user3.Username, " with roles: ", user3.Roles[0].Name, " can do : ", user3.Roles[0].Permissions[0].Name, " ", user3.Roles[0].Permissions[1].Name)

}

func connect()(*repository.CertificateDB,error){
	config := repository.PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "bojan",
		Password: "bojan",
		Name:     "bsep",
	}

	store, err := repository.Open(config)
	if err != nil {
		return nil,err
	}
	return store,nil
}
