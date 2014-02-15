package models

import (
	"fmt"
	//"github.com/robfig/revel"
	"github.com/coopernurse/gorp"
)

// Project model as stored in database
type Project struct {
	Id int

	Name, Description string
	/*
		If project is public any one with access to the website can see project and access public certs for certificates in project
		If not, only project owners and members will have visibility
	*/
	Public bool
}

// Model for mapping a user to a project that they are a member of
type ProjectMembership struct {
	Id                int
	ProjectId, UserId int

	Admin bool

	Project *Project
	User    *User
}

func (c *ProjectMembership) PreInsert(_ gorp.SqlExecutor) error {
	if c.User != nil {
		c.UserId = c.User.Id
	}

	if c.Project != nil {
		c.ProjectId = c.Project.Id
	}

	return nil
}

func (c *ProjectMembership) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.UserId != 0 {
		obj, err = exe.Get(User{}, c.UserId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate's user (%d): %s", c.UserId, err)
		}
		c.User = obj.(*User)
	}

	if c.ProjectId != 0 {
		obj, err = exe.Get(Project{}, c.ProjectId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate (%d): %s", c.ProjectId, err)
		}
		c.Project = obj.(*Project)
	}

	return nil
}
