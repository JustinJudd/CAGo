package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"github.com/JustinJudd/CAGo/app/routes"
	"code.google.com/p/go.crypto/bcrypt"
	"github.com/robfig/revel"
)

// Controller for user related actions
type User struct {
	App
}

// Get a user based on a name
func (c App) getUser(username string) *models.User {
	users, err := c.Txn.Select(models.User{}, `select * from User where Username = ?`, username)
	if err != nil {
		panic(err)
	}
	if len(users) == 0 {
		return nil
	}
	return users[0].(*models.User)
}

// Get a user based on the table index
func (c App) getUserFromId(userId int) *models.User {
	users, err := c.Txn.Select(models.User{}, `select * from User where Id = ?`, userId)
	if err != nil {
		panic(err)
	}
	if len(users) == 0 {
		return nil
	}
	return users[0].(*models.User)
}

// Check if a user is connected(logged in)
func (c App) connected() *models.User {
	if c.RenderArgs["user"] != nil {
		return c.RenderArgs["user"].(*models.User)
	}
	if username, ok := c.Session["user"]; ok {
		return c.getUser(username)
	}
	return nil
}

// Add a user to the session
func (c App) AddUser() revel.Result {
	if user := c.connected(); user != nil {
		c.RenderArgs["user"] = user
	}
	return nil
}

// Show defualt User page
func (c User) Index() revel.Result {
	if c.Session["user"] == "" {
		c.Flash.Error("Not Logged In")
		return c.Redirect(routes.App.Index())
	}

	return c.Render()
}

// Log a user in based on provided username and password
func (c User) Login(username, password string) revel.Result {
	if _, ok := c.RenderArgs["user"]; ok {
		return c.Redirect(routes.App.Index())
	}
	user := c.getUser(username)
	if user != nil {
		err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
		if err == nil {
			c.Session["user"] = username
			c.Flash.Success("Welcome, " + username)
			return c.Redirect(routes.App.Index())
		}
	}

	c.Flash.Out["username"] = username
	c.Flash.Error("Login failed")
	return c.Redirect(routes.App.Index())
}

// Show page for a new user to register
func (c User) Register() revel.Result {
	return c.Render()
}

// Show page to create a new user
func (c User) Create() revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	if !user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.App.Index())

	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Users", Url: routes.Admin.Users()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Create User", Url: routes.User.Create(), Active: true})
	return c.Render(breadcrumbs)
}

// Create and save the new user
func (c User) SaveUser(user models.User, verifyPassword string) revel.Result {
	var activeUser *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	activeUser = c.RenderArgs["user"].(*models.User)

	if !activeUser.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.App.Index())

	}

	err := c.saveUser(user, verifyPassword)
	if err != nil {
		c.Flash.Error("Unable to save user", err.Error())
		return c.Redirect(routes.User.Register())
	}

	c.Flash.Success("Created user " + user.Username)
	return c.Redirect(routes.Admin.Index())
}

// Log the current user out and close their session
func (c User) Logout() revel.Result {
	for k := range c.Session {
		delete(c.Session, k)
	}
	c.Flash.Success("Logged Out")
	return c.Redirect(routes.App.Index())
}

// Display page for the user to change their password
func (c User) Password() revel.Result {
	user := c.connected()
	if user == nil {
		return c.Redirect(routes.App.Index())
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: "/"})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: "/Admin/Index"})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Change Password", Url: "/User/Password", Active: true})

	return c.Render(user, breadcrumbs)
}

// Update the user password and update hash in database
func (c User) UpdatePassword() revel.Result {
	user := c.connected()
	if user == nil {
		return c.Redirect(routes.App.Index())
	}

	currentPassword := c.Params.Values.Get("currentPassword")
	password := c.Params.Values.Get("password")
	verifyPassword := c.Params.Values.Get("verifyPassword")

	c.Validation.Required(currentPassword)
	c.Validation.Required(password)
	c.Validation.Required(verifyPassword)

	c.Validation.Required(password == verifyPassword).
		Message("Passwords do not match")

	if c.Validation.HasErrors() {
		c.Validation.Keep()
		c.FlashParams()
		return c.Redirect(routes.User.Password())
	}

	err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(currentPassword))
	if err != nil {
		c.Flash.Error("Password provided doesn't match")
		return c.Redirect(routes.User.Password())
	}

	user.HashedPassword, _ = bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)

	_, err = c.Txn.Update(user)
	if err != nil {
		c.Flash.Error("Error Updating user")
		return c.Redirect(routes.User.Password())
	}

	c.Flash.Success("Password Changed")
	return c.Redirect(routes.App.Index())
}
