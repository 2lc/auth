 // PATH: go-auth/utils/CompareHashPassword.go

 package utils

 import "golang.org/x/crypto/bcrypt"

 func CompareHashPassword(password, hash string) bool {
     err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
     return err == nil
 }