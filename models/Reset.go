package models

import "gorm.io/gorm"

type Reset_pwds struct {
	gorm.Model
	Email string `json:"email"`
	Token string `json:"token"`
}
