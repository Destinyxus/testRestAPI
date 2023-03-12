package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{listenAddr: listenAddr,
		store: store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandleFunc(s.handleGetAccountByID), s.store))
	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))
	log.Println("JSON APIServer running on port: ", s.listenAddr)
	err := http.ListenAndServe(s.listenAddr, router)
	if err != nil {
		return
	}
}

// 9849

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("method not allowed %s", r.Method)
	}

	loginRequest := new(Login)

	err := json.NewDecoder(r.Body).Decode(loginRequest)
	if err != nil {
		return err
	}

	acc, err := s.store.GetAccountByNumber(int(loginRequest.NumberAcc))

	if !acc.ValidationPassword(loginRequest.Password) {
		return fmt.Errorf("fasfas")
	}

	token, err := createJWT(acc)
	response := AccResponse{
		Token:     token,
		NumberAcc: acc.NumberAcc,
	}
	return writeJSON(w, http.StatusOK, response)

}

// handleAccount chooses the right handler based on the certain method
func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {
		return s.handleGetAccount(w, r)
	}

	if r.Method == http.MethodPost {
		return s.handleCreateAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	acc, err := s.store.GetAccounts()
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, acc)
}

func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {

		id := mux.Vars(r)["id"]
		toInt, err := strconv.Atoi(id)
		if err != nil {

			return err

		}
		acc, err := s.store.GetAccountByID(toInt)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, acc)
	}

	if r.Method == http.MethodDelete {
		return s.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

// handleCreateAccount implements the logic of creation account with the right model from types.go
func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	createAccReq := &CreateAccountRequest{}

	if err := json.NewDecoder(r.Body).Decode(createAccReq); err != nil {
		return err
	}
	acc, err := NewAccount(createAccReq.FirstName, createAccReq.LastName, createAccReq.Password)
	if err != nil {
		return err
	}

	if err := s.store.CreateAccount(acc); err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, acc)

}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id := mux.Vars(r)["id"]
	toInt, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("wrong id %d", toInt)
	}
	if err := s.store.DeleteAccount(toInt); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]int{"deleted": toInt})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transRequest := new(TransferRequest)

	if err := json.NewDecoder(r.Body).Decode(transRequest); err != nil {
		return err
	}
	defer r.Body.Close()
	return writeJSON(w, http.StatusOK, transRequest)
}

// Converting our httpResponse to a JSON format
func writeJSON(w http.ResponseWriter, status int, value any) error {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}

func createJWT(acc *Account) (token string, err error) {
	claims := &jwt.MapClaims{
		"ExpiresAt": jwt.NewNumericDate(time.Unix(1516239022, 0)),
		"NumberAcc": acc.NumberAcc,
	}

	tokenStr := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secret := os.Getenv("JWT_SECRET")
	return tokenStr.SignedString([]byte(secret))

}

func validateJWT(token string) (*jwt.Token, error) {

	secret := os.Getenv("JWT_SECRET")
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])

		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}

func accessDenied(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, "permission denied")

}

type APIError struct {
	Error string `json:"error"`
}

func withJWTAuth(handlerFunc http.HandlerFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT auth middleware")

		tokenString := r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)
		if err != nil {
			accessDenied(w)
			return
		}
		if err != nil {
			accessDenied(w)
			return
		}
		userID, err := getID(r)
		if err != nil {
			accessDenied(w)
			return
		}
		account, err := s.GetAccountByID(userID)
		if err != nil {
			accessDenied(w)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		if account.NumberAcc != int(claims["NumberAcc"].(float64)) {
			accessDenied(w)
			return
		}

		if err != nil {
			writeJSON(w, http.StatusForbidden, APIError{Error: "invalid token"})
			return
		}

		handlerFunc(w, r)
	}
}

// Implementation of our certain handleFunc
type apiFunc func(w http.ResponseWriter, r *http.Request) error

// Converting our certain handleFunc to a Handler one
func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if err := f(writer, request); err != nil {
			writeJSON(writer, http.StatusBadRequest, APIError{Error: err.Error()})
		}
	}
}

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}
	return id, nil
}
