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

	page := &Data{Title: "Auth page", Body: "Welcome to our brand new home page.", Path: "/login", Action: "Sign In"}
	renderTemplate(c, "auth", page)
}

func Index(c *gin.Context) {
	cookie, err := c.Cookie("token")
	msg := ""
	role := ""

	if err != nil {
		//msg = "unauthorized, favor efetuar o login."
		msg = err.Error()
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

	msg := ""

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
		msg = "Invalid username or password"
		page := &Data{Title: "Auth page", Body: "Welcome to our brand new home page.", Path: "/login", Action: "Sign In", Message: msg, Role: "", Color: "Crimson", Icon: "sign-stop-fill"}
		renderTemplate(c, "auth", page)
		return
	}

	errHash := utils.CompareHashPassword(password, existingUser.Password)

	if !errHash {
		msg = "Invalid username or password"
		page := &Data{Title: "Auth page", Body: "Welcome to our brand new home page.", Path: "/login", Action: "Sign In", Message: msg, Role: "", Color: "Crimson", Icon: "sign-stop-fill"}
		renderTemplate(c, "auth", page)
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
		msg = "Could not generate token"
		page := &Data{Title: "Auth page", Body: "Welcome to our brand new home page.", Path: "/login", Action: "Sign In", Message: msg, Role: "", Color: "Crimson", Icon: "sign-stop-fill"}
		renderTemplate(c, "auth", page)
		return
	}

	c.SetCookie("token", tokenString, int(expirationTime.Unix()), "/", "auth-77wt.onrender.com", false, true)

	//page := &Data{Title: "Home page", Body: "Welcome to our brand new home page.", Path: "/home", Action: "Logout", Message: msg, Role: claims.Role}
	//renderTemplate(c, "home", page)
	c.Redirect(http.StatusFound, "home")

	//c.JSON(200, gin.H{"success": "user logged in"})
}

func Signup(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingUser models.User

	models.DB.Where("email = ?", user.Email).First(&existingUser)

	if existingUser.ID != 0 {
		c.JSON(400, gin.H{"error": "user already exists"})
		return
	}

	var errHash error
	user.Password, errHash = utils.GenerateHashPassword(user.Password)

	if errHash != nil {
		c.JSON(500, gin.H{"error": "could not generate password hash"})
		return
	}

	models.DB.Create(&user)

	c.JSON(200, gin.H{"success": "user created"})
}

func Home(c *gin.Context) {

	cookie, err := c.Cookie("token")

	if err != nil {
		//c.JSON(401, gin.H{"error1": "unauthorized"})
		c.Redirect(http.StatusFound, "/auth/")
		//return
	}
	println("Cookie: " + cookie)

	claims, err := utils.ParseToken(cookie)

	if err != nil {
		//c.JSON(401, gin.H{"error2": "unauthorized"})
		c.Redirect(http.StatusFound, "/auth/")
		//return
	}
	println(claims.ExpiresAt)
	println("Role: " + claims.Role)
	println(claims.Valid().Error())

	if claims.Role != "user" && claims.Role != "admin" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	page := &Data{Title: "Home page", Body: "Welcome to our brand new home page.", Path: "/home", Action: "Logout", Message: "", Role: claims.Role}
	renderTemplate(c, "home", page)
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
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(200, gin.H{"success": "user logged out"})
}

// ADDITIONAL FUNCTIONALITIES

func ResetPassword(c *gin.Context) {

	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var existingUser models.User

	models.DB.Where("email = ?", user.Email).First(&existingUser)

	if existingUser.ID == 0 {
		c.JSON(400, gin.H{"error": "user does not exist"})
		return
	}

	var errHash error
	user.Password, errHash = utils.GenerateHashPassword(user.Password)

	if errHash != nil {
		c.JSON(500, gin.H{"error": "could not generate password hash"})
		return
	}

	models.DB.Model(&existingUser).Update("password", user.Password)

	c.JSON(200, gin.H{"success": "password updated"})
}
