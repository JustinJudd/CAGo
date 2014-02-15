package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"github.com/JustinJudd/CAGo/app/routes"
	"fmt"
	"github.com/robfig/revel"

	//"crypto/tls"

	//"encoding/hex"
	//"encoding/base64"
)

// Tour section for first time the App is run
type Tour struct {
	App
}

// Start page of tour - setup server
func (c Tour) Index() revel.Result {
	return c.Render()
}

// Form to create first user
func (c Tour) User() revel.Result {
	return c.Render()
}

// Form to create first project
func (c Tour) Project() revel.Result {
	return c.Render()
}

// Create and Save first project
func (c Tour) SaveProject(project models.Project) revel.Result {

	err := c.saveProject(project)
	if err != nil {
		c.Flash.Error("Error creating project")
		return c.Redirect(routes.Tour.Project())
	}

	c.Flash.Success("Project " + project.Name + " created")
	//fmt.Println(user)
	return c.Redirect(routes.Admin.Index())
}

// Create and Save first project
func (c Tour) SaveServerInfo(serverURL string) revel.Result {

	if len(serverURL) == 0 {
		c.Flash.Error("Unable to save server info")
		return c.Redirect(routes.Tour.Index())
	}
	server := &models.Server{URL: serverURL}
	err := c.Txn.Insert(server)
	if err != nil {
		c.Flash.Error("Unable to save server info")
		return c.Redirect(routes.Tour.Index())
	}

	c.Flash.Success("Server info saved")
	//fmt.Println(user)
	return c.Redirect(routes.Tour.User())
}

// Save the first user
func (c Tour) SaveUser(user models.User, verifyPassword string) revel.Result {
	err := c.saveUser(user, verifyPassword)
	if err != nil {
		c.Flash.Error("Unable to save user", err.Error())
		return c.Redirect(routes.Tour.User())
	}

	c.Session["user"] = user.Username
	c.Flash.Success("Created, " + user.Username)
	fmt.Println(user)
	return c.Redirect(routes.Tour.Project())
}
