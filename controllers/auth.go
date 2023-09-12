// PATH: go-auth/controllers/auth.go
package controllers

import (
	"auth/models"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"auth/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Data struct {
	Title   string
	Body    string
	Path    string
	Action  string
	Message string
	Color   string
	Icon    string
	Role    string
	User    []models.User
}

type Dtkt struct {
	Title   string
	Body    string
	Path    string
	Message string
	Usuario string
	Color   string
	Icon    string
	Ticket  []models.Ticket
}

type v_tickets struct {
	Id         string
	Usuario    string
	Grupo      string
	Data       string
	Status     string
	Ocorrencia string
}

var msgerror, cor, icone string

var jwtKey = []byte("my_secret_key")

var templates = template.Must(template.ParseGlob("templates/*")).Funcs(template.FuncMap{"lpad": lpad})

func lpad(str string) string {
	for len(str) < 6 {
		str = "0" + str
	}
	return str
}

func renderTemplate(c *gin.Context, tmpl string, page *Data) {
	err := templates.ExecuteTemplate(c.Writer, tmpl, page)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Auth(c *gin.Context) {
	page := &Data{Title: "Auth page", Body: "Welcome to our brand new home page.", Path: "/login", Action: "Sign In", Message: msgerror, Color: cor, Icon: icone}
	renderTemplate(c, "auth", page)
}

func Index(c *gin.Context) {
	cookie, err := c.Cookie("token")
	msg := ""
	role := ""
	msgerror = ""

	if err != nil {
		msg = err.Error()
		msgerror = "Autenticação requerida, faça um novo login."
		cor = "Gold"
		icone = "exclamation-triangle-fill"
		c.Redirect(http.StatusFound, "auth")
	}

	claims, err := utils.ParseToken(cookie)

	if err != nil {
		msg = err.Error()
		//return
	} else {
		role = claims.Role
	}

	//if claims.Role != "user" && claims.Role != "admin" {
	//	msg = "unauthorized, sem perfil de acesso."
	//return
	//}
	//println(msg)

	page := &Data{Title: "Index page", Body: "Welcome to our brand new index page.", Path: "/auth", Action: "Login", Message: msg, Role: role}

	renderTemplate(c, "index", page)

}

func Login(c *gin.Context) {

	msgerror = ""

	email := c.PostForm("email")
	password := c.PostForm("password")

	//if err := c.ShouldBindJSON(&user); err != nil {
	//	c.JSON(400, gin.H{"error": err.Error()})
	//	return
	//}

	var existingUser models.User

	//models.DB.Where("email = ?", user.Email).First(&existingUser)
	models.DB.Where("email = ?", email).First(&existingUser)

	if existingUser.ID == 0 {
		msgerror = "Invalid username or password"
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "auth")
		return
	}

	errHash := utils.CompareHashPassword(password, existingUser.Password)

	if !errHash {
		msgerror = "Invalid username or password"
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "auth")
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &models.Claims{
		Role: existingUser.Role,
		StandardClaims: jwt.StandardClaims{
			Subject:   existingUser.Email,
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		msgerror = "Could not generate token"
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "auth")
		return
	}

	c.SetCookie("token", tokenString, int(expirationTime.Unix()), "/", "auth-77wt.onrender.com", false, true)

	//page := &Data{Title: "Home page", Body: "Welcome to our brand new home page.", Path: "/home", Action: "Logout", Message: msg, Role: claims.Role}
	//renderTemplate(c, "home", page)
	c.Redirect(http.StatusFound, "home")

	//c.JSON(200, gin.H{"success": "user logged in"})
}

func Register(c *gin.Context) {
	page := &Data{Title: "Register page", Body: "Welcome to our brand new home page.", Path: "/register", Action: "Register", Message: msgerror, Color: cor, Icon: icone}
	renderTemplate(c, "register", page)
}

func Signup(c *gin.Context) {
	var user models.User

	msgerror = ""
	user.Name = c.PostForm("name")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")
	user.Role = "User"

	var existingUser models.User

	models.DB.Where("email = ?", user.Email).First(&existingUser)

	if existingUser.ID != 0 {
		cor = "Gold"
		icone = "exclamation-triangle-fill"
		msgerror = "user already exists"
	}

	var errHash error
	user.Password, errHash = utils.GenerateHashPassword(user.Password)

	if errHash != nil {
		cor = "Gold"
		icone = "exclamation-triangle-fill"
		msgerror = "could not generate password hash"
	}

	if msgerror == "" {
		models.DB.Create(&user)
		cor = "#03c03c"
		icone = "check-circle-fill"
		msgerror = "User created sucessfull."
	}

	c.Redirect(http.StatusFound, "register")
}

func Home(c *gin.Context) {

	cookie, err := c.Cookie("token")

	if err != nil {
		msgerror = err.Error()
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "/auth/")
	}

	claims, err := utils.ParseToken(cookie)

	if err != nil {
		msgerror = err.Error()
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "/auth/")
	} else {
		if claims.Role != "user" && claims.Role != "admin" {
			http.Error(c.Writer, "Acesso Não autorizado.", http.StatusUnauthorized)
			return
		}
		page := &Data{Title: "Home page", Body: "Welcome to our brand new home page.", Path: "/logout", Action: "Logout", Message: "", Role: claims.Role}
		renderTemplate(c, "home", page)
	}

}

func Premium(c *gin.Context) {
	cookie, err := c.Cookie("token")

	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	claims, err := utils.ParseToken(cookie)

	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	if claims.Role != "admin" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(200, gin.H{"success": "premium page", "role": claims.Role})

}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "auth-77wt.onrender.com", false, true)
	//c.JSON(200, gin.H{"success": "user logged out"})
	http.Error(c.Writer, "Logout realizado.", http.StatusOK)
	msgerror = ""
}

// ADDITIONAL FUNCTIONALITIES

func ResetPassword(c *gin.Context) {

	var reset models.Reset_pwds

	//if err := c.ShouldBindJSON(&user); err != nil {
	//	c.JSON(400, gin.H{"error": err.Error()})
	//	return
	//}

	email := c.PostForm("recipient")

	var existingUser models.User

	models.DB.Where("email = ?", email).First(&existingUser)

	if existingUser.ID == 0 {
		msgerror = "user does not exist"
		cor = "Gold"
		icone = "exclamation-triangle-fill"
		c.Redirect(http.StatusFound, "/auth/")
		return
	} else {

		auth := smtp.PlainAuth("", "lcabral@gmail.com", "zypgehjyydbrzxjf", "smtp.gmail.com")

		token, err := bcrypt.GenerateFromPassword([]byte(email), 14)

		if err != nil {
			msgerror = err.Error()
			cor = "Crimson"
			icone = "sign-stop-fill"
			c.Redirect(http.StatusFound, "/auth/")
			return
		}

		if msgerror == "" {
			reset.Email = email
			reset.Token = string(token)
			models.DB.Create(&reset)
		}

		link := "http://localhost:8080/auth/reset/" + string(token)

		// Here we do it all: connect to our server, set up a message and send it

		to := []string{"lcabral@leader.com.br"}

		msg := []byte("To: lcabral@leader.com.br\r\n" +

			"Subject: Reset de senha\r\n" +

			"\r\n" +

			"Para criar uma nova senha, favor ccessar o link: " + link +

			"\r\n")

		err = smtp.SendMail("smtp.gmail.com:587", auth, "lcabral@gmail.com", to, msg)

		if err != nil {
			log.Fatal(err)
		}
		msgerror = "Um email com o link de reset foi enviado para " + email
		cor = "#03c03c"
		icone = "check-circle-fill"
	}
	c.Redirect(http.StatusFound, "/auth/")
	//var errHash error
	//user.Password, errHash = utils.GenerateHashPassword(user.Password)

	//if errHash != nil {
	//	c.JSON(500, gin.H{"error": "could not generate password hash"})
	//	return
	//}

	//models.DB.Model(&existingUser).Update("password", user.Password)

	//c.JSON(200, gin.H{"success": "password updated"})

}

func ListUsers(c *gin.Context) {

	Usu := make([]models.User, 0)
	models.DB.Order("id").Find(&Usu)

	page := &Data{Title: "User page", Body: "Lista de usuários", Path: "/users", Action: "Home", Message: "", Role: "", User: Usu}
	err := templates.ExecuteTemplate(c.Writer, "userslist", page)
	if err != nil {
		log.Println(err)
		http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
		return
	}
}

func Users(c *gin.Context) {
	/*
		Usu := make([]models.User, 0)
		models.DB.Find(&Usu)

		page := &Data{Title: "User page", Body: "Lista de usuários", Path: "/users", Action: "Home", Message: "", Role: "", User: Usu}
		err := templates.ExecuteTemplate(c.Writer, "userslist", page)
		if err != nil {
			log.Println(err)
			http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
			return
		}*/
	id := c.Param("id")
	acao := c.Param("acao")
	nome := c.PostForm("name")
	role := c.PostForm("role")
	reset := c.PostForm("reset")

	if c.Request.Method == "GET" {

		Usr := make([]models.User, 0)

		models.DB.Where("ID = ?", id).First(&Usr)

		log.Println("ID: " + id)
		page := &Data{Title: "User Manutenção", Body: "Manutenção de usuários", Path: "/users", Action: "Home", Message: "", Role: "", User: Usr}
		err := templates.ExecuteTemplate(c.Writer, "users", page)
		if err != nil {
			log.Println(err)
			http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
			return
		}

	} else {
		if acao == "1" {
			var existingUser models.User
			var num_reg int64

			models.DB.Where("ID = ?", id).First(&existingUser).Count(&num_reg)

			if num_reg == 0 {
				cor = "Gold"
				icone = "exclamation-triangle-fill"
				msgerror = "user NOT already exists"
				return
			}

			/*var errHash error
			existingUser.Password, errHash = utils.GenerateHashPassword(existingUser.Password)

			if errHash != nil {
				cor = "Gold"
				icone = "exclamation-triangle-fill"
				msgerror = "could not generate password hash"
			}*/

			if msgerror == "" {
				models.DB.Where("ID = ?", id).Updates(models.User{Name: nome, Role: role})
				cor = "#03c03c"
				icone = "check-circle-fill"
				msgerror = "User created sucessfull."
			} else {
				log.Println(msgerror)
			}
		} else {
			err := models.DB.Delete(&models.User{}, id).Error
			if err == nil {
				cor = "#03c03c"
				icone = "check-circle-fill"
				msgerror = "User deleted sucessfull."
			} else {
				log.Println(err.Error())
			}
		}
		c.Redirect(http.StatusFound, "/users")
	}
	if reset == "on" {
		log.Println("Entrei aqui!!! " + reset)
	}

}

func Tickets(c *gin.Context) {

	/*
		Usu := make([]models.User, 0)
		models.DB.Find(&Usu)

		page := &Data{Title: "User page", Body: "Lista de usuários", Path: "/users", Action: "Home", Message: "", Role: "", User: Usu}
		err := templates.ExecuteTemplate(c.Writer, "userslist", page)
		if err != nil {
			log.Println(err)
			http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
			return
		}*/
	dt_format := "02/01/2006 15:04:05"
	Tkt := make([]models.Ticket, 0)
	Usr := make([]models.User, 0)
	id := c.Param("id")
	acao := c.Param("acao")
	ocorrencia := c.PostForm("ocorrencia")
	grupoatendimento := c.PostForm("grupoatendimento")
	//reset := c.PostForm("reset")
	Usuario := ""

	if c.Request.Method == "GET" {

		//log.Println("Entrei aqui!!! ")

		if id != "" {
			err := models.DB.Where("ID = ?", id).First(&Tkt).Error
			
			if err != nil {
				log.Println(err)
				http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
				return
			}
			usr_id := Tkt[0].UserAbertura
			models.DB.Where("ID = ?", usr_id).First(&Usr)
			Usuario = Usr[0].Name
		} else {
			//models.DB.Find(&Tkt)
			var tk models.Ticket
			tk.ID = 0
			tk.GrupoAtendimento = ""
			tk.Ocorrencia = ""
			Tkt = append(Tkt, tk)
		}

		Abertura := Tkt[0].CreatedAt.Format(dt_format)

		page := &Dtkt{Title: "Tickets", Body: "Abertura de Tickets", Path: "/tickets", Message: Abertura, Usuario: Usuario, Ticket: Tkt}
		err := templates.ExecuteTemplate(c.Writer, "tickets", page)
		if err != nil {
			log.Println(err)
			http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
			return
		}

	} else {
		if acao == "1" {
			var existingTicket models.Ticket

			models.DB.Where("ID = ?", id).First(&existingTicket)

			if existingTicket.ID != 0 {
				models.DB.Where("ID = ?", id).Updates(models.Ticket{Ocorrencia: ocorrencia, GrupoAtendimento: grupoatendimento})
				cor = "#03c03c"
				icone = "check-circle-fill"
				msgerror = "User Altered sucessfull."
			} else {
				existingTicket.Ocorrencia = ocorrencia
				existingTicket.GrupoAtendimento = grupoatendimento
				models.DB.Create(&existingTicket)
				cor = "#03c03c"
				icone = "check-circle-fill"
				msgerror = "User created sucessfull."
				Tkt = append(Tkt, existingTicket)

				Abertura := Tkt[0].CreatedAt.Format(dt_format)

				page := &Dtkt{Title: "Tickets", Body: "Abertura de Tickets", Path: "/tickets", Message: Abertura, Ticket: Tkt}
				err := templates.ExecuteTemplate(c.Writer, "tickets", page)
				if err != nil {
					log.Println(err)
					http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
					return
				}
			}
		} else {
			err := models.DB.Delete(&models.Ticket{}, id).Error
			if err == nil {
				cor = "#03c03c"
				icone = "check-circle-fill"
				msgerror = "User deleted sucessfull."
			} else {
				log.Println(err.Error())
			}
		}
		c.Redirect(http.StatusFound, "/")
	}
}

func ListTickets(c *gin.Context) {

	type Dtkts struct {
		Title   string
		Body    string
		Path    string
		Message string
		Color   string
		Icon    string
		Ticket  []v_tickets
	}

	Tkts := make([]v_tickets, 0)
	models.DB.Find(&Tkts)

	page := &Dtkts{Title: "Ticket page", Body: "Lista de tickets", Path: "/tickets/lista", Message: "", Ticket: Tkts}
	err := templates.ExecuteTemplate(c.Writer, "ticketslist", page)
	if err != nil {
		log.Println(err)
		http.Error(c.Writer, "there was an error", http.StatusInternalServerError)
		return
	}
}
