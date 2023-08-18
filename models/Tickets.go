package models

import (
	"gorm.io/gorm"
)

type Ticket struct {
	gorm.Model
	UserAbertura     uint
	UserAtendimento  uint
	Status           int
	GrupoAtendimento string
	Ocorrencia       string
	Atendimento      []Atendimentos
}

type Atendimentos struct {
	gorm.Model
	Seq        uint
	Tipo       string
	Tratamento string
	TicketID   uint
}
