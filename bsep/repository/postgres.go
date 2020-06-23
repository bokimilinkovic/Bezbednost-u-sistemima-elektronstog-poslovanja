package repository

import (
	"bsep/model"
	mrand "math/rand"
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

const (
	PW_SALT_BYTES = 32
	PW_HASH_BYTES = 64
    letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)


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
		hashedPass := cdb.HashPassword("admin","admin")
		user := &model.User{
			Username: "admin",
			PasswordHash: hashedPass,
			Salt: "admin",
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
	salt := RandomString(6)
	fmt.Println(salt)
	passwordHash := cdb.HashPassword(salt ,password)
	user := &model.User{
		Username: username,
		PasswordHash: passwordHash,
		Salt: salt,
	}
	defaultRole := &model.Role{Name:"Client"}
	defaultPermission := &model.Permission{Name:"Visit"}
	defaultRole.Permissions = append(defaultRole.Permissions,defaultPermission)
	user.Roles = append(user.Roles,defaultRole)
	cdb.db.Create(&user)
	return user
}

func(cdb *CertificateDB)HashPassword(salt, password string) string{
	hash, err := bcrypt.GenerateFromPassword([]byte(password + salt), bcrypt.DefaultCost)
	if err != nil {
		panic("Permissions: bcrypt password hasnig unsuccessful")
	}
	return string(hash)
}

func(cdb *CertificateDB)CheckPassword(user *model.User, password string) bool {
	passToCompare := password + user.Salt
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(passToCompare)) != nil {
		return  false
	}
	return  true
}

func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		b[i] = letter[mrand.Intn(len(letter))]
	}
	return string(b)
}
