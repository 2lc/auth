// PATH: go-auth/controllers/auth.go
package controllers

import (
	"auth/models"
	"html/template"
	"net/http"
	"time"

	"auth/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
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
}

var msgerror, cor, icone string

var jwtKey = []byte("my_secret_key")

var templates = template.Must(template.ParseGlob("templates/*"))

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
		c.Redirect(http.StatusFound, "/auth")
	}

	errHash := utils.CompareHashPassword(password, existingUser.Password)

	if !errHash {
		msgerror = "Invalid username or password"
		cor = "Crimson"
		icone = "sign-stop-fill"
		c.Redirect(http.StatusFound, "/auth")
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

	//var user models.User

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
	} else {
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
