package main

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Login struct {
	NumberAcc int    `json:"number_acc"`
	Password  string `json:"password"`
}

type AccResponse struct {
	NumberAcc int    `json:"number_acc"`
	Token     string `json:"token"`
}

type CreateAccountRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
}

type Account struct {
	ID                int       `json:"id"`
	FirstName         string    `json:"first_name"`
	Lastname          string    `json:"last_name"`
	Balance           int       `json:"balance"`
	NumberAcc         int       `json:"number_acc"`
	EncryptedPassword string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
}

func (a *Account) ValidationPassword(pswd string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pswd)) == nil
}

type TransferRequest struct {
	ToAccount int `json:"to_account"`
	Amount    int `json:"amount"`
}

func NewAccount(firstName string, lastname string, password string) (*Account, error) {
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Account{
		FirstName:         firstName,
		Lastname:          lastname,
		EncryptedPassword: string(encryptedPassword),
		NumberAcc:         rand.Intn(10000),
		CreatedAt:         time.Now().UTC(),
	}, nil
}
