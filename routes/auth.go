// PATH: go-auth/routes/auth.go

package routes

import (
	"auth/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	r.GET("/", controllers.Index)
	r.GET("/auth", controllers.Auth)
	r.GET("/register", controllers.Register)
	r.POST("/register", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.POST("/signup", controllers.Signup)
	r.GET("/home", controllers.Home)
	r.GET("/premium", controllers.Premium)
	r.GET("/logout", controllers.Logout)
	r.POST("/reset", controllers.ResetPassword)
	r.GET("/users", controllers.ListUsers)
	r.GET("/users/:id", controllers.Users)
	r.POST("/users/:id/:acao", controllers.Users)
	//r.GET("/tickets/lista", controllers.ListTickets)
	r.GET("/tickets", controllers.Tickets)
	r.GET("/tickets/:id", controllers.Tickets)
	r.POST("/tickets/:id/:acao", controllers.Tickets)
}
