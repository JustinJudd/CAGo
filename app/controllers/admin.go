package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"github.com/JustinJudd/CAGo/app/routes"
	"github.com/robfig/revel"
	"strconv"
	"strings"

	"crypto/x509"
	"encoding/pem"

	"crypto/x509/pkix"
	"encoding/asn1"
)

// Controller for admin sections of the project
type Admin struct {
	App
}

// Base index page for Admin Controller - List Admin options
func (c Admin) Index() revel.Result {
	users := c.getUsers()
	if len(users) == 0 {
		return c.Redirect(routes.Tour.Index())
	}

	user := c.connected()
	if user == nil {
		return c.Render()
	}

	isProjectOwner := c.isProjectOwner(user.Id)
	anyAdmin := isProjectOwner || user.IsAdmin

	projects := c.getUserProjects(user)
	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index(), Active: true})

	return c.Render(projects, breadcrumbs, isProjectOwner, anyAdmin)
}

// Admin controller - List users and access, create users
func (c Admin) Users() revel.Result {
	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	if !user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}
	users := c.getUsers()
	if len(users) == 0 {
		return c.Redirect(routes.Tour.Index())
	}

	projects := make(map[int][]*models.Project)

	for _, user := range users {
		projects[user.Id] = c.getUserProjects(user)
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Users", Url: routes.Admin.Users(), Active: true})

	return c.Render(users, projects, breadcrumbs)
}

// Edit a user and their accesses
func (c Admin) EditUser(userId int) revel.Result {

	var loggedin_user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	loggedin_user = c.RenderArgs["user"].(*models.User)

	if !loggedin_user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	user := c.getUserFromId(userId)

	admin_projects := c.getUserProjects(user)
	all_projects := c.getProjects()

	project_map := make(map[int]bool, len(all_projects))

	for _, project := range all_projects {
		project_map[project.Id] = false
		for _, p := range admin_projects {
			if p.Id == project.Id {
				project_map[project.Id] = true
			}
		}
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Users", Url: routes.Admin.Users()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit User", Url: routes.Admin.EditUser(userId), Active: true})

	return c.Render(user, all_projects, admin_projects, project_map, breadcrumbs)
}

// Save the user
func (c Admin) SaveUser(userId int, user models.User) revel.Result {
	var loggedin_user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	loggedin_user = c.RenderArgs["user"].(*models.User)

	if !loggedin_user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}
	if user.Id != userId {
		c.Flash.Error("Error updating user")
		return c.Redirect(routes.Admin.Index())
	}

	edit_user := c.getUserFromId(user.Id)
	edit_user.Name = user.Name
	edit_user.Email = user.Email
	edit_user.IsAdmin = user.IsAdmin

	edit_user.Validate(c.Validation)

	if c.Validation.HasErrors() {
		c.Validation.Keep()
		c.FlashParams()
		c.Flash.Error("Error Updating user")
		return c.Redirect(routes.Admin.EditUser(edit_user.Id))
		//return c.Redirect(routes.User.Register())
	}

	admin_projects := c.getUserProjects(edit_user)
	all_projects := c.getProjects()

	project_map := make(map[int]bool, len(all_projects))

	for _, project := range all_projects {
		project_map[project.Id] = false
		for _, p := range admin_projects {
			if p.Id == project.Id {
				project_map[project.Id] = true
			}
		}
	}

	projects := c.Params.Values["projectOwnership"]

	add := make([]int, 0)
	remove := make([]int, 0)

	revel.INFO.Println(project_map, projects)

	// Find projects to add
	for _, proj := range projects {
		p, _ := strconv.Atoi(proj)
		if !project_map[p] {
			add = append(add, p)
		}
	}
	for proj, owned := range project_map {
		if owned {
			found := false
			for _, p := range projects {
				p1, _ := strconv.Atoi(p)
				if p1 == proj {
					found = true
				}
			}
			if !found {
				remove = append(remove, proj)
			}
		}
	}
	revel.INFO.Println("ADD:", add)
	revel.INFO.Println("REMOVE:", remove)

	_, err := c.Txn.Update(edit_user)
	if err != nil {
		c.Flash.Error("Error Updating user")
		return c.Redirect(routes.Admin.EditUser(edit_user.Id))
	}
	updateMembership := make([]interface{}, len(remove))
	for i, r := range remove {
		m := c.getProjectMembership(r, edit_user.Id)
		m.Admin = false
		updateMembership[i] = m
	}

	addMembership := make([]interface{}, 0)
	for _, a := range add {
		exists := c.getProjectMembership(a, edit_user.Id)
		if exists != nil {
			exists.Admin = true
			updateMembership = append(updateMembership, exists)
		} else {
			addMembership = append(addMembership, &models.ProjectMembership{ProjectId: a, User: edit_user, Admin: true})
		}

	}

	_, err = c.Txn.Update(updateMembership...)
	if err != nil {
		c.Flash.Error("Error Updating user")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.EditUser(edit_user.Id))
	}

	err = c.Txn.Insert(addMembership...)
	if err != nil {
		c.Flash.Error("Error Updating user")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.EditUser(edit_user.Id))
	}

	c.Flash.Success("Updated, " + edit_user.Username)
	return c.Redirect(routes.Admin.Index())
}

// Create a new project through admin portal
func (c Admin) Project() revel.Result {
	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	if !user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Create Project", Url: routes.Admin.Project(), Active: true})
	return c.Render(breadcrumbs)
}

// Manage projects
func (c Admin) Projects() revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	isProjectOwner := c.isProjectOwner(user.Id)

	if !user.IsAdmin && !isProjectOwner {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	projects := c.getProjects()
	owned_projects := c.getUsersProjects(user.Id)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects(), Active: true})

	return c.Render(projects, breadcrumbs, owned_projects, user)
}

// Manage a project
func (c Admin) ManageProject(id int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	isProjectOwner := c.isProjectOwner(user.Id)
	if !user.IsAdmin && !owns && !isProjectOwner {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	templates := c.getProjectCertTemplates(project)

	certs := c.getProjectCerts(project)

	csrs := c.getProjectsCSRs(project.Id)

	owners_certs := c.getUserCerts(user)
	cert_map := make(map[int]bool, 0)
	for _, cert := range certs {
		for _, c := range owners_certs {
			if c.Id == cert.Id {
				cert_map[c.Id] = true
			}
		}
	}
	project_members := c.getProjectMembers(id)

	revoked := c.getProjectsRevokedCerts(id)
	revokedMap := make(map[int]bool, len(revoked))
	for _, r := range revoked {
		revokedMap[r.Certificate.Id] = true
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage " + project.Name + " Project", Url: routes.Admin.ManageProject(id), Active: true})

	return c.Render(project, breadcrumbs, templates, certs, cert_map, project_members, project_owners, csrs, revokedMap)
}

// Edit a project
func (c Admin) EditProject(id int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	templates := c.getProjectCertTemplates(project)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage " + project.Name + " Project", Url: routes.Admin.ManageProject(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit Project", Url: routes.Admin.EditProject(id), Active: true})

	return c.Render(project, breadcrumbs, templates)
}

// Update and save a project and store it in database
func (c Admin) UpdateProject(id int, project models.Project) revel.Result {

	if project.Id != id {
		c.Flash.Error("Error updating project")
		return c.Redirect(routes.Admin.Index())
	}

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	_, err := c.Txn.Update(&project)
	if err != nil {
		c.Flash.Error("Error creating project")
		return c.Redirect(routes.Admin.Project())
	}

	c.Flash.Success("Project " + project.Name + " created")
	return c.Redirect(routes.Admin.Index())

}

// Create and save a project and store it in database
func (c Admin) SaveProject(project models.Project) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	if !user.IsAdmin {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	err := c.saveProject(project)
	if err != nil {
		c.Flash.Error("Error creating project")
		return c.Redirect(routes.Admin.Project())
	}

	c.Flash.Success("Project " + project.Name + " created")
	return c.Redirect(routes.Admin.Index())

}

// Present View to make new certificate template
func (c Admin) NewTemplate(id int) revel.Result {

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.App.Index())
	}

	if project.Id != id {
		c.Flash.Error("Error accessing project")
		return c.Redirect(routes.Admin.Index())
	}

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	cas := c.getProjectCAs(project)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage " + project.Name + " Project", Url: routes.Admin.ManageProject(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "New Template", Url: routes.Admin.NewTemplate(id), Active: true})

	return c.Render(project, cas, breadcrumbs)
}

// Create a certificate template based on the passsed in form, and save it in the database
func (c Admin) CreateTemplate(id int, template models.CertificateTemplate) revel.Result {

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.Admin.Index())
	}

	if project.Id != id {
		c.Flash.Error("Error accessing project")
		return c.Redirect(routes.Admin.Index())
	}

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	template.Project = project

	template.KeyUses = strings.Join(c.Params.Values["template.KeyUses"], ", ")
	template.ExtKeyUses = strings.Join(c.Params.Values["template.ExtKeyUses"], ", ")
	revel.INFO.Println(template)

	err := c.Txn.Insert(&template)
	if err != nil {
		c.Flash.Error("Error creating certificate template", err)
		return c.Redirect(routes.Admin.Index())
	}

	c.Flash.Success("Certificate template " + template.Name + " created")
	return c.Redirect(routes.Admin.Index())
}

// Edit a template
func (c Admin) EditTemplate(id, templateId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	template := c.getProjectCertTemplate(templateId)
	cas := c.getProjectCAs(project)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Projects", Url: routes.Admin.Projects()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage " + project.Name + " Project", Url: routes.Admin.ManageProject(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit Template", Url: routes.Admin.EditTemplate(id, templateId), Active: true})

	return c.Render(project, breadcrumbs, template, cas)
}

// Update a certificate template based on the passsed in form, and save it in the database
func (c Admin) UpdateTemplate(id int, template models.CertificateTemplate) revel.Result {

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access template")
		return c.Redirect(routes.Admin.Index())
	}
	if project.Id != id {
		c.Flash.Error("Error accessing project")
		return c.Redirect(routes.Admin.Index())
	}

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	t := c.getCertTemplate(template.Id)
	if t.Project.Id != id {
		c.Flash.Error("Unable to access template")
		return c.Redirect(routes.Admin.Index())
	}
	template.Name = t.Name
	template.Project = project
	template.ProjectId = project.Id

	template.KeyUses = strings.Join(c.Params.Values["template.KeyUses"], ", ")
	template.ExtKeyUses = strings.Join(c.Params.Values["template.ExtKeyUses"], ", ")
	revel.INFO.Println(template)

	_, err := c.Txn.Update(&template)
	if err != nil {
		c.Flash.Error("Error updating certificate template", err)
		return c.Redirect(routes.Admin.Index())
	}

	c.Flash.Success("Certificate template " + template.Name + " updated")
	return c.Redirect(routes.Admin.Index())
}

// Edit a projects membership list
func (c Admin) EditProjectMembership(projectId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(projectId)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	members := c.getProjectMembers(project.Id)
	all_users := c.getUsers()
	users_map := make(map[int]*models.User, len(all_users))

	owner_map := make(map[int]bool, len(all_users))
	member_map := make(map[int]bool, len(all_users))

	for _, user := range all_users {
		users_map[user.Id] = user
		owner_map[user.Id] = false
		member_map[user.Id] = false
	}

	for _, member := range members {
		member_map[member.Id] = true
	}

	for _, owner := range project_owners {
		owner_map[owner.Id] = true
		member_map[owner.Id] = false
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Project", Url: routes.Admin.ManageProject(projectId)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit Project Membership", Url: routes.Admin.EditProjectMembership(projectId), Active: true})

	return c.Render(project, breadcrumbs, member_map, owner_map, users_map)
}

// Save the project membership changes
func (c Admin) SaveProjectMembership(projectId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(projectId)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	owners := c.Params.Values["projectOwnership"]
	members := c.Params.Values["projectMembership"]

	//revel.INFO.Println("Owners: ", owners)
	//revel.INFO.Println("Members: ", members)

	all_members := c.getProjectMembers(project.Id)
	all_users := c.getUsers()
	users_map := make(map[int]*models.User, len(all_users))

	owner_map := make(map[int]bool, len(all_users))
	member_map := make(map[int]bool, len(all_users))
	seen_map := make(map[int]bool, len(all_users))

	for _, user := range all_users {
		users_map[user.Id] = user
		owner_map[user.Id] = false
		member_map[user.Id] = false
		seen_map[user.Id] = false
	}

	for _, owner := range project_owners {
		owner_map[owner.Id] = true
	}

	for _, member := range all_members {
		member_map[member.Id] = true
	}

	member_add := make([]int, 0)    // Users moved from non-member to either member or admin
	member_remove := make([]int, 0) // Users moved from member or admin to nonmember
	member_update := make([]int, 0) // uSers moved from admin to member or member to admin

	// Find owners to add or update
	for _, owner := range owners {
		o, _ := strconv.Atoi(owner)
		seen_map[o] = true
		if !owner_map[o] {
			if member_map[o] {
				member_update = append(member_update, o)
			} else {
				member_add = append(member_add, o)
			}

		}
	}
	for _, member := range members {
		m, _ := strconv.Atoi(member)
		seen_map[m] = true
		if !member_map[m] {
			if owner_map[m] {
				member_update = append(member_update, m)
			} else {
				member_add = append(member_add, m)
			}
		}
	}
	for member, seen := range seen_map {
		if !seen {
			member_remove = append(member_remove, member)
		}
	}
	revel.INFO.Println("MEMBER ADD:", member_add)
	revel.INFO.Println("MEMBER REMOVE:", member_remove)
	revel.INFO.Println("MEMBER UPDATE:", member_update)

	removeMembership := make([]interface{}, len(member_remove))
	for i, r := range member_remove {
		removeMembership[i] = c.getProjectMembership(project.Id, r)

	}

	addMembership := make([]interface{}, len(member_add))
	for i, a := range member_add {
		addMembership[i] = &models.ProjectMembership{Project: project, UserId: a}

	}

	updateMembership := make([]interface{}, len(member_update))
	for i, u := range member_update {
		updateUser := users_map[u]
		toUpdate := c.getProjectMembership(project.Id, updateUser.Id)
		toUpdate.Admin = !toUpdate.Admin
		updateMembership[i] = toUpdate
	}

	_, err := c.Txn.Delete(removeMembership...)
	if err != nil {
		c.Flash.Error("Error removing user member")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.ManageProject(project.Id))
	}

	err = c.Txn.Insert(addMembership...)
	if err != nil {
		c.Flash.Error("Error adding user member")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.ManageProject(project.Id))
	}

	_, err = c.Txn.Update(updateMembership...)
	if err != nil {
		c.Flash.Error("Error updating user member")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.ManageProject(project.Id))
	}

	c.Flash.Success("Updated Project membership")
	return c.Redirect(routes.Admin.ManageProject(project.Id))
}

// Edit a certificate ownership list
func (c Admin) EditCertificate(projectId, certId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(projectId)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}
	if project.Id != projectId {
		c.Flash.Error("Error updating project")
		return c.Redirect(routes.Admin.Index())
	}

	cert_owners := c.getCertificateOwners(certId)
	project_owners := c.getProjectOwners(projectId)
	//owners := c.getProjectMembers(project.Id)
	project_users := c.getProjectUsers(project.Id)
	users_map := make(map[int]*models.User, len(project_users))

	owner_map := make(map[int]bool, len(project_users))
	owns := false
	project_owner := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
			project_owner = true
		}
	}

	for _, user := range project_users {
		users_map[user.Id] = user
		owner_map[user.Id] = false
	}

	cert_owner := false
	for _, owner := range cert_owners {
		owner_map[owner.Id] = true
		if owner.Id == user.Id {
			owns = true
			cert_owner = true
		}
	}

	revel.INFO.Println(cert_owners)
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	certificate := c.getCert(certId)
	if certificate == nil {
		c.Flash.Error("Error loading certificate")
		return c.Redirect(routes.Admin.Index())
	}

	block, _ := pem.Decode(certificate.PEM)
	if block == nil {
		//fmt.Printf("%s\n", rest)
	}
	//fmt.Printf("%s\n", block)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Flash.Error("Error parsing certificate\n", err)
		return c.Redirect(routes.Admin.Index())
	}
	keyUses := make([]string, 0)
	if x509.KeyUsageDigitalSignature|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Digital Signature")
	}
	if x509.KeyUsageContentCommitment|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Content Commitment")
	}
	if x509.KeyUsageKeyEncipherment|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Key Encipherment")
	}
	if x509.KeyUsageDataEncipherment|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Data Encipherment")
	}
	if x509.KeyUsageKeyAgreement|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Key Agreement")
	}
	if x509.KeyUsageCertSign|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Cert Sign")
	}
	if x509.KeyUsageCRLSign|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "CRL Sign")
	}
	if x509.KeyUsageEncipherOnly|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Encipher Only")
	}
	if x509.KeyUsageDecipherOnly|cert.KeyUsage == cert.KeyUsage {
		keyUses = append(keyUses, "Decipher Only")
	}

	extKeyUses := make([]string, 0)
	for _, use := range cert.ExtKeyUsage {

		switch use {
		case x509.ExtKeyUsageServerAuth:
			extKeyUses = append(extKeyUses, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUses = append(extKeyUses, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUses = append(extKeyUses, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUses = append(extKeyUses, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			extKeyUses = append(extKeyUses, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			extKeyUses = append(extKeyUses, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			extKeyUses = append(extKeyUses, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUses = append(extKeyUses, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUses = append(extKeyUses, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUses = append(extKeyUses, "MS Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUses = append(extKeyUses, "Netscape Server Gated Crypto")

		}
	}

	verify, err := c.buildCertPools(project)
	if err != nil {
		c.Flash.Error("Unable to load certificates")
		return c.Redirect(routes.Admin.Index())
	}

	chains, err := cert.Verify(*verify)
	if err != nil {
		c.Flash.Error("Unable to verify certificate")
		return c.Redirect(routes.Admin.Index())
	}

	canDownloadKey := user.IsAdmin || cert_owner || project_owner
	canRevokeKey := user.IsAdmin || project_owner

	revoked := c.isRevoked(certId)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Project", Url: routes.Admin.ManageProject(projectId)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit Certificate", Url: routes.Admin.EditCertificate(projectId, certId), Active: true})

	return c.Render(project, certificate, breadcrumbs, owner_map, users_map, cert, chains, keyUses, extKeyUses, canDownloadKey, canRevokeKey, revoked)
}

// Save the project membership changes
func (c Admin) UpdateCertificate(projectId, certId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(projectId)
	if project == nil {
		return c.Redirect(routes.App.Index())
	}

	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	cert_owners := c.getCertificateOwners(certId)
	for _, owner := range cert_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	owners := c.Params.Values["certificateOwnership"]
	project_users := c.getProjectUsers(project.Id)
	owner_map := make(map[int]bool, len(project_users))
	users_map := make(map[int]*models.User, len(project_users))

	for _, user := range project_users {
		users_map[user.Id] = user
		owner_map[user.Id] = false
	}

	for _, owner := range cert_owners {
		owner_map[owner.Id] = true
	}

	owner_add := make([]int, 0)
	owner_remove := make([]int, 0)

	// Find users to add
	for _, owner := range owners {
		o, _ := strconv.Atoi(owner)
		if !owner_map[o] {
			owner_add = append(owner_add, o)
		}
	}
	for owner, owned := range owner_map {
		if owned {
			found := false
			for _, o := range owners {
				o1, _ := strconv.Atoi(o)
				if o1 == owner {
					found = true
				}
			}
			if !found {
				owner_remove = append(owner_remove, owner)
			}
		}
	}

	certificate := c.getCert(certId)
	if certificate == nil {
		c.Flash.Error("Error loading certificate")
		return c.Redirect(routes.Project.Index(projectId))
	}

	removeOwnership := make([]interface{}, len(owner_remove))
	for i, r := range owner_remove {
		removeOwnership[i] = c.getCertificateOwnership(certificate.Id, r)

	}

	addOwnership := make([]interface{}, len(owner_add))
	for i, a := range owner_add {
		addOwnership[i] = &models.CertificateOwnership{Certificate: certificate, UserId: a}

	}

	_, err := c.Txn.Delete(removeOwnership...)
	if err != nil {
		c.Flash.Error("Error removing user owner")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.ManageProject(project.Id))
	}

	err = c.Txn.Insert(addOwnership...)
	if err != nil {
		c.Flash.Error("Error inserting user owner")
		revel.INFO.Println(err)
		return c.Redirect(routes.Admin.ManageProject(project.Id))
	}

	c.Flash.Success("Updated Certificate ownership")
	return c.Redirect(routes.Admin.ManageProject(project.Id))
}

// Sign a CSR in the database
func (c Admin) SignCSR(projectId, csrId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)
	project := c.getProject(projectId)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}
	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.ManageProject(projectId))

	}
	cas := c.getProjectCAs(project)

	csr := c.getCSR(projectId, csrId)
	if csr == nil {
		c.Flash.Error("Unable to find Certificate Request")
		return c.Redirect(routes.Admin.ManageProject(projectId))
	}

	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		c.Flash.Error("Error PEM decoding CSR")
		return c.Redirect(routes.Admin.ManageProject(projectId))
	}
	parsed_csr, err := ParseCertificationRequest(block.Bytes)
	if err != nil {
		c.Flash.Error("Error Decoding CSR")
		return c.Redirect(routes.Admin.ManageProject(projectId))
	}

	var out pkix.Name
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(parsed_csr.CertificationRequestInfo.Subject.FullBytes, &subject); err != nil {
		c.Flash.Error(err.Error())
		return c.Redirect(routes.Admin.ManageProject(projectId))
	}

	out.FillFromRDNSequence(&subject)

	//If we get to this point we were successfully able to parse the CSR

	certificate := &models.FullCertificate{}

	certificate.Country = out.Country[0]
	certificate.Organization = out.Organization[0]
	certificate.OrganizationUnit = out.OrganizationalUnit[0]
	certificate.State = out.Province[0]
	certificate.City = out.Locality[0]
	certificate.CommonName = out.CommonName

	requestedCA := csr.RequestedCA

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Project", Url: routes.Admin.ManageProject(projectId)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Sign Certificate Request", Url: routes.Admin.SignCSR(projectId, csrId), Active: true})

	return c.Render(project, certificate, breadcrumbs, cas, requestedCA, csr)

}

// Create and sign a certificate from CSR and save in the database
func (c Admin) SaveSignCSR(projectId, csrId int, certificate models.FullCertificate) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)
	project := c.getProject(projectId)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}
	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.ManageProject(projectId))

	}

	csr := c.getCSR(projectId, csrId)
	if csr == nil {
		c.Flash.Error("Unable to find Certificate Request")
		return c.Redirect(routes.Admin.ManageProject(projectId))
	}

	cert, err := c.createCertificate(projectId, certificate)
	if err != nil {
		c.Flash.Error("Error creating cert", err.Error())
		return c.Redirect(routes.Project.Index(project.Id))
	}

	// Just add cert ownership for CSR Requester
	certOwnership := models.CertificateOwnership{Certificate: cert, User: csr.User}
	err = c.Txn.Insert(&certOwnership)
	if err != nil {
		c.Flash.Error("Unable to create certificate ownership", err.Error())
		return c.Redirect(routes.Project.Index(project.Id))
	}
	_, err = c.Txn.Delete(csr)
	if err != nil {
		c.Flash.Error("Unable to delete certificate request", err.Error())
		return c.Redirect(routes.Project.Index(project.Id))
	}

	c.Flash.Success("Certificate created")
	return c.Redirect(routes.Project.Index(project.Id))

}

// Revoke a certificate and store it in the database
func (c Admin) RevokeCertificate(projectId, certId int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)
	project := c.getProject(projectId)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.Admin.Index())
	}
	project_owners := c.getProjectOwners(projectId)
	owns := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin && !owns {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.ManageProject(projectId))

	}

	certificate := c.getCert(certId)
	if certificate == nil {
		c.Flash.Error("Error loading certificate")
		return c.Redirect(routes.Admin.EditCertificate(projectId, certId))
	}
	revoked := &models.RevokedCertificate{Certificate: certificate}

	err := c.Txn.Insert(revoked)
	if err != nil {
		c.Flash.Error("Unable to save revoked certificate info")
		return c.Redirect(routes.Admin.EditCertificate(projectId, certId))
	}

	c.Flash.Success("Certificate has been revoked")
	return c.Redirect(routes.Admin.ManageProject(projectId))

}
