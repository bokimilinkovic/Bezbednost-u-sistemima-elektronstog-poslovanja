package model

type User struct {
	ID int `gorm:"primary_key"`
	Username string `gorm:"not null;unique"`
	PasswordHash string `gorm:"not null" json:"-"`
	Roles []*Role `gorm:"many2many:user_roles;"`
}

type Role struct{
	ID int `gorm:"primary_key"`
	Name string
	Users []*User `gorm:"many2many:user_roles;"`
	Permissions []*Permission `gorm:"many2many:permission_roles;"`
}

type Permission struct{
	ID int `gorm:"primary_key"`
	Name string
	Roles []*Role `gorm:"many2many:permission_roles;"`
}