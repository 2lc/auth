// PATH: go-auth/routes/auth.go

package routes

import (
    "auth/controllers"

    "github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
    r.GET("/", controllers.Index)
    r.GET("/auth",controllers.Auth)
    r.POST("/login", controllers.Login)
    r.POST("/signup", controllers.Signup)
    r.GET("/home", controllers.Home)
    r.GET("/premium", controllers.Premium)
    r.GET("/logout", controllers.Logout)
    r.POST("/reset", controllers.ResetPassword)
}