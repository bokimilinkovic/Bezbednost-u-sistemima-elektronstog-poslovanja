package repository

import (
	"bsep/model"
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type CertificateDB struct {
	db *gorm.DB
}

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
}

func NewCertificateDB(db *gorm.DB) *CertificateDB {
	return &CertificateDB{db: db}
}

func Open(config PostgresConfig) (*CertificateDB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.User, config.Password, config.Name)

	db, err := gorm.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	store := NewCertificateDB(db)
	return store, nil
}

func (cdb *CertificateDB) AutoMigrate() error {
	if err := cdb.db.AutoMigrate(&model.User{}).Error; err != nil {
		return err
	}
	var count int
	if err := cdb.db.Table("users").Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		user := &model.User{
			Username: "admin",
			//Password: "admin",
		}
		err := cdb.db.Create(&user).Error
		if err != nil {
			return err
		}
	}
	if err := cdb.db.AutoMigrate(&model.Revoked{}).Error; err != nil {
		return err
	}

	return nil
}

func (cdb *CertificateDB) Close() error {
	return cdb.db.Close()
}

func (cdb *CertificateDB) ValidateUser(username string, pass string) error {
	user := &model.User{}
	err := cdb.db.Find(&user, "username = $1", username).Error
	if err != nil {
		return err
	}
	//if user.Password != pass {
	//	return errors.New("Invalid password")
	//}
	return nil
}

func (cdb *CertificateDB) RevokeCertificat(i int) error {
	revoked := &model.Revoked{
		CertificatID:   i,
		RevocationTime: time.Now(),
	}
	return cdb.db.Create(revoked).Error
}

func (cdb *CertificateDB) GetAllRevoked() ([]*model.Revoked, error) {
	revoked := []*model.Revoked{}
	if err := cdb.db.Find(&revoked).Error; err != nil {
		return nil, err
	}
	return revoked, nil
}

func(cdb *CertificateDB)DB() *gorm.DB{
	return cdb.db
}

func(cdb *CertificateDB)HasUser(username string)bool {
	if err := cdb.db.Where("username = ?", username).Find(&model.User{}).Error; err != nil {
		return false
	}
	return true
}

func(cdb *CertificateDB)FindUser(username string) *model.User{
	user := &model.User{}
	cdb.db.Preload("Roles.Permissions").Where("username = ?", username).Find(&user)
	return user
}

func(cdb *CertificateDB)FindUserByID(id int)(*model.User, error){
	user := &model.User{}
	err := cdb.db.Preload("Roles.Permissions").Where("id = ?", id).Find(&user).Error
	if err != nil {
		return nil,err
	}

	return user, nil
}

func(cdb *CertificateDB)AddUser(username, password string)*model.User{
	passwordHash := cdb.HashPassword(username,password)
	user := &model.User{
		Username: username,
		PasswordHash: passwordHash,
	}
	cdb.db.Create(&user)
	return user
}

func(cdb *CertificateDB)HashPassword(username, password string) string{
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic("Permissions: bcrypt password hasnig unsuccessful")
	}
	return string(hash)
}

func(cdb *CertificateDB)CheckPassword(hashedPass, password string) bool {
	if bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(password)) != nil {
		return  false
	}
	return  true
}
