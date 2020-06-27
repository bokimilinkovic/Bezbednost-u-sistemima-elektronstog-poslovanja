package service

import "bsep/repository"

type UserService struct{
	DB *repository.CertificateDB
}

func NewUserService(db *repository.CertificateDB)*UserService{
	return &UserService{DB:db}
}

func(us *UserService)HasUser(username string)bool{
	return us.DB.HasUser(username)
}

func(us *UserService) Activate(username string)error{
	return us.DB.ActivateUser(username)
}