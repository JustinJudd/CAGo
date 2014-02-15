package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"github.com/JustinJudd/CAGo/app/routes"
	"github.com/robfig/revel"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net/http"

	"crypto/sha1"
	"encoding/base64"

	"crypto/rand"
	"errors"
	"math/big"
)

// Project controller
type Project struct {
	App
}

// Get a project with specified ID from database
func (c App) getProject(projectId int) *models.Project {
	projects, err := c.Txn.Select(models.Project{}, `select * from Project where Id = ?`, projectId)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}

	return projects[0].(*models.Project)
}

// Get a list of all projects from database
func (c App) getProjects() []*models.Project {
	projects, err := c.Txn.Select(models.Project{}, `select * from Project`)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}
	projects_list := make([]*models.Project, len(projects), len(projects))
	for i, project := range projects {
		projects_list[i] = project.(*models.Project)
	}

	return projects_list
}

// Get a certificate with specified ID from database
func (c App) getCert(certId int) *models.Certificate {
	certs, err := c.Txn.Select(models.Certificate{}, `select * from Certificate where Id = ?`, certId)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}

	return certs[0].(*models.Certificate)
}

// Get a certificate template with specified ID from database
func (c App) getCertTemplate(id int) *models.CertificateTemplate {
	templates, err := c.Txn.Select(models.CertificateTemplate{}, `select * from CertificateTemplate where Id = ?`, id)
	if err != nil {
		panic(err)
	}
	if len(templates) == 0 {
		return nil
	}

	return templates[0].(*models.CertificateTemplate)
}

// Get a certificate template with specified name from database
func (c App) getCertTemplateByName(name string) *models.CertificateTemplate {
	templates, err := c.Txn.Select(models.CertificateTemplate{}, `select * from CertificateTemplate where name = ?`, name)
	if err != nil {
		panic(err)
	}
	if len(templates) == 0 {
		return nil
	}

	return templates[0].(*models.CertificateTemplate)
}

// Get a list of all users that own a given project from database
func (c App) getProjectOwners(projectId int) []*models.User {
	projects, err := c.Txn.Select(models.ProjectMembership{}, `select * from ProjectMembership where ProjectId = ? and Admin = 1`, projectId)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}

	owners_list := make([]*models.User, len(projects), len(projects))
	for i, project := range projects {
		owners_list[i] = project.(*models.ProjectMembership).User
	}

	return owners_list
}

// Get a list of all projects that a given user is an owner of from database
func (c App) getUsersProjects(userId int) []*models.Project {
	projects, err := c.Txn.Select(models.Project{}, `select Project.* from ProjectMembership, Project where ProjectMembership.UserId = ? and Admin = 1 and ProjectMembership.ProjectId = Project.Id`, userId)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}

	project_list := make([]*models.Project, len(projects), len(projects))
	for i, project := range projects {
		project_list[i] = project.(*models.Project)
	}

	return project_list
}

// Get a list of all projects that should be visible to a given user
func (c App) getVisibleProjects(userId int) []*models.Project {
	// Two places to check, public projects, and projects that the user is a member of - use a map as a set to ensure uniqueness
	project_map := make(map[int]bool, 0)
	user_projects, err := c.Txn.Select(models.Project{}, `select Project.* from ProjectMembership, Project where ProjectMembership.UserId = ? and Admin = 1 and ProjectMembership.ProjectId = Project.Id`, userId)
	if err != nil {
		panic(err)
	}

	public_projects, err := c.Txn.Select(models.Project{}, `select * from Project where Public = 1`)
	if err != nil {
		panic(err)
	}

	project_list := make([]*models.Project, len(user_projects), len(user_projects))
	for i, project := range user_projects {
		project_list[i] = project.(*models.Project)
		project_map[project_list[i].Id] = true
	}
	for _, project := range public_projects {
		p := project.(*models.Project)
		if !project_map[p.Id] {
			project_list = append(project_list, p)
		}

	}

	return project_list
}

// Get a list of all users that are members of a given project from database
func (c App) getProjectMembers(projectId int) []*models.User {
	projects, err := c.Txn.Select(models.ProjectMembership{}, `select * from ProjectMembership where ProjectId = ?`, projectId)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}

	members_list := make([]*models.User, len(projects), len(projects))
	for i, project := range projects {
		members_list[i] = project.(*models.ProjectMembership).User
	}

	return members_list
}

// Get a list of all users that are in given project from database(Users+Admins)
func (c App) getProjectUsers(projectId int) []*models.User {
	members_list := c.getProjectOwners(projectId)
	members_list = append(members_list, c.getProjectMembers(projectId)...)

	return members_list
}

// Get a boolean if the user owns any projects
func (c App) isProjectOwner(userId int) bool {
	projects, err := c.Txn.Select(models.Project{}, `select Project.* from ProjectMembership, Project where ProjectMembership.UserId = ? and ProjectMembership.Admin = 1 and ProjectMembership.ProjectId = Project.Id`, userId)
	if err != nil {
		panic(err)
	}
	return len(projects) > 0
}

// Get a list of all users that own a given certificate from database
func (c App) getCertificateOwners(certId int) []*models.User {
	certs, err := c.Txn.Select(models.CertificateOwnership{}, `select * from CertificateOwnership where CertificateId = ?`, certId)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}

	owners_list := make([]*models.User, len(certs), len(certs))
	for i, cert := range certs {
		owners_list[i] = cert.(*models.CertificateOwnership).User
	}

	return owners_list
}

// Get a project ownership struct for a given user and project from database
func (c App) getCertificateOwnership(certId, userId int) *models.CertificateOwnership {
	certs, err := c.Txn.Select(models.CertificateOwnership{}, `select * from CertificateOwnership where CertificateId = ? and UserId = ?`, certId, userId)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}
	return certs[0].(*models.CertificateOwnership)
}

// Get a project membership struct for a given user and project from database
func (c App) getProjectMembership(projectId, userId int) *models.ProjectMembership {
	projects, err := c.Txn.Select(models.ProjectMembership{}, `select * from ProjectMembership where ProjectId = ? and UserId = ?`, projectId, userId)
	if err != nil {
		panic(err)
	}
	if len(projects) == 0 {
		return nil
	}
	return projects[0].(*models.ProjectMembership)
}

// Get a one time link based on a given hash from the database
func (c App) getOneTimeLink(hash string) *models.CertificateOneTimeDownload {
	certs, err := c.Txn.Select(models.CertificateOneTimeDownload{}, `select * from CertificateOneTimeDownload where Hash = ?`, hash)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}

	return certs[0].(*models.CertificateOneTimeDownload)
}

// Get a list of certificates within a project from the database
func (c App) getProjectCerts(project *models.Project) []*models.Certificate {
	certs, err := c.Txn.Select(models.Certificate{}, `select Certificate.* from Certificate, Project where Project.Id = ? and Certificate.ProjectId = Project.Id`, project.Id)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}
	certs_list := make([]*models.Certificate, len(certs), len(certs))
	for i, cert := range certs {
		certs_list[i] = cert.(*models.Certificate)
	}
	return certs_list
}

// Get a list of certificates for a user from the database
func (c App) getUserCerts(user *models.User) []*models.Certificate {
	certs, err := c.Txn.Select(models.Certificate{}, `select Certificate.* from Certificate, CertificateOwnership where CertificateOwnership.UserId = ? and Certificate.Id = CertificateOwnership.CertificateId`, user.Id)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}
	certs_list := make([]*models.Certificate, len(certs), len(certs))
	for i, cert := range certs {
		certs_list[i] = cert.(*models.Certificate)
	}
	return certs_list
}

// Get a certificate template  from the database
func (c App) getProjectCertTemplate(id int) *models.CertificateTemplate {
	templates, err := c.Txn.Select(models.CertificateTemplate{}, `select * from CertificateTemplate where id = ?`, id)
	if err != nil {
		panic(err)
	}
	if len(templates) == 0 {
		return nil
	}
	return templates[0].(*models.CertificateTemplate)
}

// Get a list of certificate templates within a project from the database
func (c App) getProjectCertTemplates(project *models.Project) []*models.CertificateTemplate {
	templates, err := c.Txn.Select(models.CertificateTemplate{}, `select CertificateTemplate.* from CertificateTemplate, Project where Project.Id = ? and CertificateTemplate.ProjectId = Project.Id`, project.Id)
	if err != nil {
		panic(err)
	}
	if len(templates) == 0 {
		return nil
	}
	templates_list := make([]*models.CertificateTemplate, len(templates), len(templates))
	for i, template := range templates {
		templates_list[i] = template.(*models.CertificateTemplate)
	}
	return templates_list
}

// Get a list of all certificates that are CAs within a project from the database
func (c App) getProjectCAs(project *models.Project) []*models.Certificate {
	certs, err := c.Txn.Select(models.Certificate{}, `select Certificate.* from Certificate, Project where Project.Id = ? and Certificate.ProjectId = Project.Id and Certificate.CA = 1`, project.Id)
	if err != nil {
		panic(err)
	}
	if len(certs) == 0 {
		return nil
	}
	certs_list := make([]*models.Certificate, len(certs), len(certs))
	for i, cert := range certs {
		certs_list[i] = cert.(*models.Certificate)
	}
	return certs_list
}

// Get all CSRs that a given user is able to sign from database
func (c App) getSignableCSRs(userId int) []*models.CertificateRequest {
	csrs, err := c.Txn.Select(models.CertificateRequest{}, `select CertificateRequest.* from CertificateRequest, ProjectMembership where ProjectMembership.UserId = ? and ProjectMembership.Admin = 1 and CertificateRequest.ProjectId = ProjectMembership.ProjectId `, userId)
	if err != nil {
		panic(err)
	}
	if len(csrs) == 0 {
		return nil
	}
	csr_list := make([]*models.CertificateRequest, len(csrs), len(csrs))
	for i, csr := range csrs {
		csr_list[i] = csr.(*models.CertificateRequest)
	}
	return csr_list
}

// Get all CSRs are under a given project from database
func (c App) getProjectsCSRs(projectId int) []*models.CertificateRequest {
	csrs, err := c.Txn.Select(models.CertificateRequest{}, `select * from CertificateRequest where ProjectId = ? `, projectId)
	if err != nil {
		panic(err)
	}
	if len(csrs) == 0 {
		return nil
	}
	csr_list := make([]*models.CertificateRequest, len(csrs), len(csrs))
	for i, csr := range csrs {
		csr_list[i] = csr.(*models.CertificateRequest)
	}
	return csr_list
}

// Get a CSR from database based on ID
func (c App) getCSR(projectId, csrId int) *models.CertificateRequest {
	csrs, err := c.Txn.Select(models.CertificateRequest{}, `select * from CertificateRequest where Id = ? and ProjectId = ?`, csrId, projectId)
	if err != nil {
		panic(err)
	}
	if len(csrs) == 0 {
		return nil
	}
	return csrs[0].(*models.CertificateRequest)
}

// Get a count of total CAs in CAGo
func (c App) getCRLCount() int {
	crlCount, err := c.Txn.SelectInt(`select count(*) from CACount`)
	if err != nil {
		panic(err)
	}
	return int(crlCount)
}

// Get a list of revoked certificates  from the database
func (c App) getAllRevokedCerts() []*models.RevokedCertificate {
	var revoked []*models.RevokedCertificate
	_, err := c.Txn.Select(&revoked, `select * from RevokedCertificate`)
	if err != nil {
		panic(err)
	}
	return revoked
}

// Get a list of revoked certificates for a project from the database
func (c App) getProjectsRevokedCerts(projectId int) []*models.RevokedCertificate {
	var revoked []*models.RevokedCertificate
	_, err := c.Txn.Select(&revoked, `select RevokedCertificate.* from RevokedCertificate, Certificate where Certificate.ProjectId = ? and RevokedCertificate.CertificateId = Certificate.Id`, projectId)
	if err != nil {
		panic(err)
	}
	return revoked
}

// Inquire from DB if certificate is revoked
func (c App) isRevoked(certId int) bool {
	certCount, err := c.Txn.SelectInt(`select count(*) from RevokedCertificate where CertificateId = ?`, certId)
	if err != nil {
		panic(err)
	}
	return int(certCount) != 0
}

// Build a certificate pool for a project
func (c App) buildCertPools(project *models.Project) (*x509.VerifyOptions, error) {
	certs := c.getProjectCerts(project)

	certPools := make([]*x509.CertPool, 2)
	certPools[0] = x509.NewCertPool()
	certPools[1] = x509.NewCertPool()

	root_pems := make([]byte, 0)
	other_pems := make([]byte, 0)
	for _, cert := range certs {
		if cert.CA {
			block, _ := pem.Decode(cert.PEM)
			if block == nil {
				return nil, errors.New("Error decoding certificate")
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			if c.Issuer.CommonName == cert.CommonName {
				root_pems = append(root_pems, cert.PEM...)
			} else {
				other_pems = append(other_pems, cert.PEM...)
			}

		}

	}

	certPools[0].AppendCertsFromPEM(root_pems)
	certPools[1].AppendCertsFromPEM(other_pems)

	verify := &x509.VerifyOptions{Roots: certPools[0], Intermediates: certPools[1], KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	return verify, nil

}

// Get the base Project page
func (c Project) Index(id int) revel.Result {
	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}

	certs := c.getProjectCerts(project)

	var user *models.User
	if c.RenderArgs["user"] != nil {
		user = c.RenderArgs["user"].(*models.User)
	}

	revoked := c.getProjectsRevokedCerts(id)
	revokedMap := make(map[int]bool, len(revoked))
	for _, r := range revoked {
		revokedMap[r.Certificate.Id] = true
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: project.Name + " Project", Url: routes.Project.Index(id), Active: true})

	/* - Can be used to build chains
	verify, err := c.buildCertPools(project)
	if err != nil {
		c.Flash.Error("Unable to verify certificates")
		return c.Redirect(routes.App.Index())
	}
	*/

	templates := c.getProjectCertTemplates(project)

	return c.Render(project, certs, breadcrumbs, templates, user, revokedMap)
}

// Present the page/form to create a certificate
func (c Project) CreateCert(id int) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)
	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Project not found")
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
	cas := c.getProjectCAs(project)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Project", Url: routes.Admin.ManageProject(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Edit Certificate", Url: routes.Project.CreateCert(id), Active: true})

	return c.Render(project, cas, breadcrumbs)
}

// Present the page/form to create a certificate based on a template
func (c Project) CreateCertFromTemplate(projectId, templateId int) revel.Result {
	project := c.getProject(projectId)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}
	cas := c.getProjectCAs(project)

	template := c.getProjectCertTemplate(templateId)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Admin", Url: routes.Admin.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Manage Project", Url: routes.Admin.ManageProject(projectId)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Create Certificate", Url: routes.Project.CreateCertFromTemplate(projectId, templateId), Active: true})

	return c.Render(project, cas, breadcrumbs, template)
}

// Display page for viewing certificate information
func (c Project) ViewCert(projectId, certId int) revel.Result {
	project := c.getProject(projectId)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}

	certificate := c.getCert(certId)
	if certificate == nil {
		c.Flash.Error("Error loading certificate")
		return c.Redirect(routes.Project.Index(projectId))
	}

	var user *models.User
	if c.RenderArgs["user"] == nil {
		user = &models.User{IsAdmin: false}
	} else {
		user = c.RenderArgs["user"].(*models.User)
	}

	cert_owners := c.getCertificateOwners(certId)
	cert_owner := false
	for _, owner := range cert_owners {
		if owner.Id == user.Id {
			cert_owner = true
		}
	}
	project_owners := c.getProjectOwners(projectId)
	project_owner := false
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			project_owner = true
		}
	}
	canDownloadKey := user.IsAdmin || cert_owner || project_owner
	canRevokeKey := user.IsAdmin || project_owner
	revoked := c.isRevoked(certId)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: project.Name + " Project", Url: routes.Project.Index(projectId)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "View Certificate", Url: routes.Project.ViewCert(projectId, certId), Active: true})

	block, _ := pem.Decode(certificate.PEM)
	if block == nil {
		c.Flash.Error("Error PEM decding certificate\n")
		return c.Redirect(routes.Project.Index(projectId))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Flash.Error("Error parsing certificate\n", err)
		return c.Redirect(routes.Project.Index(projectId))
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
		return c.Redirect(routes.App.Index())
	}

	chains, err := cert.Verify(*verify)
	if err != nil {
		c.Flash.Error("Unable to verify certificate")
		return c.Redirect(routes.App.Index())
	}

	return c.Render(project, cert, certificate, breadcrumbs, keyUses, extKeyUses, canDownloadKey, canRevokeKey, chains, revoked)
}

// Create a certificate based on the passsed in form, and save it in the database
func (c Project) CreateCertificate(id int, certificate models.FullCertificate) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.Admin.Index())
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

	cert, err := c.createCertificate(id, certificate)
	if err != nil {
		c.Flash.Error("Error creating cert", err.Error())
		return c.Redirect(routes.Project.Index(project.Id))
	}
	certOwnership := models.CertificateOwnership{Certificate: cert, User: user}
	err = c.Txn.Insert(&certOwnership)
	if err != nil {
		c.Flash.Error("Unable to create certificate ownership", err.Error())
		return c.Redirect(routes.Project.Index(project.Id))
	}
	c.Flash.Success("Certificate created")
	return c.Redirect(routes.Admin.ManageProject(project.Id))
}

// Load/Import a Certificate Signing Request
func (c Project) LoadCSR(id int) revel.Result {
	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.Admin.Index())
	}
	project_members := c.getProjectUsers(id)
	isMember := false
	for _, member := range project_members {
		if member.Id == user.Id {
			isMember = true
		}
	}
	if !user.IsAdmin && !isMember {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	cas := c.getProjectCAs(project)

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: project.Name + " Project", Url: routes.Project.Index(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Load CSR", Url: routes.Project.LoadCSR(id), Active: true})

	return c.Render(project, cas, breadcrumbs)
}

// Store a passed CSR to be signed
func (c Project) SaveCSR(id int, csr *models.CertificateRequest) revel.Result {

	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.Admin.Index())
	}
	project_members := c.getProjectUsers(id)
	isMember := false
	for _, member := range project_members {
		if member.Id == user.Id {
			isMember = true
		}
	}
	if !user.IsAdmin && !isMember {
		c.Flash.Error("You do not have permissions for this page")
		return c.Redirect(routes.Admin.Index())

	}

	csr.Project = project
	csr.User = user
	csr.CSR = []byte(c.Params.Values["csr.CSR"][0])
	cas := c.getProjectCAs(project)
	for _, ca := range cas {
		if csr.RequestedCAId == ca.Id {
			csr.RequestedCA = ca
			break
		}
	}
	if csr.RequestedCA == nil {
		c.Flash.Error("Error finding requested CA")
		return c.Redirect(routes.Project.LoadCSR(id))
	}

	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		c.Flash.Error("Error PEM decoding CSR")
		return c.Redirect(routes.Project.LoadCSR(id))
	}
	parsed_csr, err := ParseCertificationRequest(block.Bytes)
	if err != nil {
		c.Flash.Error("Error Decoding CSR")
		return c.Redirect(routes.Project.LoadCSR(id))
	}

	var out pkix.Name
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(parsed_csr.CertificationRequestInfo.Subject.FullBytes, &subject); err != nil {
		c.Flash.Error(err.Error())
		return c.Redirect(routes.Project.LoadCSR(id))
	}

	out.FillFromRDNSequence(&subject)
	//If we get to this point we were successfully able to parse the CSR

	// Save CSR to database
	err = c.Txn.Insert(csr)
	if err != nil {
		c.Flash.Error("Error saving CSR", err.Error())
		return c.Redirect(routes.Project.LoadCSR(id))
	}

	c.Flash.Success("Submitted CSR for signing")
	return c.Redirect(routes.Project.Index(id))
}

// Custom string type to wrap my own functions around
type Download string

// This will get called for Cert/Key downloads to manage HTTP Headers
func (r Download) Apply(req *revel.Request, resp *revel.Response) {
	resp.WriteHeader(http.StatusOK, "text/plain") //Browser can open
	//resp.WriteHeader(http.StatusOK, "application/text")//Forces Browser to download
	resp.Out.Write([]byte(r))
}

// Download a certificate in PEM format
func (c Project) Download(id, certId int) revel.Result {
	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}
	cert := c.getCert(certId)
	if cert == nil {
		c.Flash.Error("Certificate not found")
		return c.Redirect(routes.Project.Index(id))
	}

	return Download(cert.PEM)
}

// Download a certificate chain in PEM format
func (c Project) DownloadChain(id, certId int) revel.Result {
	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Project not found")
		return c.Redirect(routes.App.Index())
	}
	certificate := c.getCert(certId)
	if certificate == nil {
		c.Flash.Error("Certificate not found")
		return c.Redirect(routes.Project.Index(id))
	}
	block, _ := pem.Decode(certificate.PEM)
	if block == nil {
		c.Flash.Error("Unable to decode certificate")
		return c.Redirect(routes.Project.Index(id))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Flash.Error("Error parsing certificate\n", err)
		return c.Redirect(routes.Project.Index(id))
	}

	verify, err := c.buildCertPools(project)
	if err != nil {
		c.Flash.Error("Unable to load certificates")
		return c.Redirect(routes.Project.Index(id))
	}

	chains, err := cert.Verify(*verify)
	if err != nil {
		c.Flash.Error("Unable to verify certificate")
		return c.Redirect(routes.Project.Index(id))
	}

	chained_pem := ""
	for _, c := range chains[0] {
		chained_pem += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	return Download(chained_pem)
}

// Download a key in PEM format
func (c Project) DownloadKey(id, certId int) revel.Result {
	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to access project")
		return c.Redirect(routes.App.Index())
	}
	cert := c.getCert(certId)

	cert_owners := c.getCertificateOwners(certId)
	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range cert_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin || !owns {
		c.Flash.Error("You do not have permissions to download the key")
		return c.Redirect(routes.Project.Index(project.Id))

	}

	return Download(cert.PrivateKey)
}

// Download an encrypted key in PEM format
func (c Project) DownloadEncryptedKey(id, certId int, newKey, existingKey string) revel.Result {
	var user *models.User
	if c.RenderArgs["user"] == nil {
		c.Flash.Error("You must log in first")
		return c.Redirect(routes.App.Index())
	}

	user = c.RenderArgs["user"].(*models.User)

	project := c.getProject(id)
	if project == nil {
		c.Flash.Error("Unable to load project")
		return c.Redirect(routes.App.Index())
	}
	cert := c.getCert(certId)

	if cert == nil {
		c.Flash.Error("Unable to load certificate")
		return c.Redirect(routes.App.Index())
	}

	cert_owners := c.getCertificateOwners(certId)
	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range cert_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin || !owns {
		c.Flash.Error("You do not have permissions to download the key")
		return c.Redirect(routes.Project.Index(project.Id))

	}

	block, _ := pem.Decode(cert.PrivateKey)
	if block == nil {
		c.Flash.Error("Unable to decode certificate")
		return c.Redirect(routes.Project.Index(project.Id))
	}
	bytes := block.Bytes
	var err error
	// Need to decrypt if the key stored in the database is encrypted
	if len(existingKey) != 0 {
		bytes, err = x509.DecryptPEMBlock(block, []byte(existingKey))
		if err != nil {
			c.Flash.Error("Error decrypting initial key")
			return c.Redirect(routes.Project.Index(project.Id))
		}
	}
	var keyType string
	switch cert.KeyType {
	case models.RSA:
		keyType = "RSA PRIVATE KEY"
	case models.ECDSA:
		keyType = "EC PRIVATE KEY"
	}

	pemKeyBlock := &pem.Block{Type: keyType, Bytes: bytes}
	if len(newKey) > 0 {
		pemKeyBlock, err = x509.EncryptPEMBlock(rand.Reader, pemKeyBlock.Type, pemKeyBlock.Bytes, []byte(newKey), x509.PEMCipherAES256)
		if err != nil {
			c.Flash.Error("Error encrypting key")
			return c.Redirect(routes.Project.Index(project.Id))
		}
	} else {
		c.Flash.Error("Need valid encryption key")
		return c.Redirect(routes.Project.Index(project.Id))
	}
	privCert := pem.EncodeToMemory(pemKeyBlock)

	return Download(privCert)
}

// Generate a One Time Link to allow download of a key
func (c Project) GenerateOneTimeLink(id, certId int) revel.Result {
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
	cert := c.getCert(certId)

	cert_owners := c.getCertificateOwners(certId)
	project_owners := c.getProjectOwners(id)
	owns := false
	for _, owner := range cert_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	for _, owner := range project_owners {
		if owner.Id == user.Id {
			owns = true
		}
	}
	if !user.IsAdmin || !owns {
		c.Flash.Error("You do not have permissions to download the key")
		return c.Redirect(routes.Project.Index(project.Id))

	}

	certDownload := models.CertificateOneTimeDownload{}
	certDownload.Certificate = cert
	hasher := sha1.New()
	hasher.Write([]byte(time.Now().String() + cert.CommonName))
	certDownload.Hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	// Save Certificate link to database
	err := c.Txn.Insert(&certDownload)
	if err != nil {
		c.Flash.Error("Error creating One-Time download link", err)
		return c.Redirect(routes.Project.Index(project.Id))
	}

	breadcrumbs := make([]BreadCrumb, 0)
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Home", Url: routes.App.Index()})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: project.Name + " Project", Url: routes.Project.Index(id)})
	breadcrumbs = append(breadcrumbs, BreadCrumb{Name: "Generate One-Time Link", Url: routes.Project.GenerateOneTimeLink(id, certId), Active: true})

	return c.Render(certDownload)
}

// Use One Time Link to download the private key
func (c App) DownloadOneTimeLink(hash string) revel.Result {
	onetime := c.getOneTimeLink(hash)
	if onetime == nil {
		return c.Redirect(routes.App.Index())
	}

	_, err := c.Txn.Delete(onetime)
	if err != nil {
		c.Flash.Error("Error deleting One-Time download link", err)
		return c.Redirect(routes.App.Index())
	}

	return Download(append(onetime.Certificate.PEM, onetime.Certificate.PrivateKey...))
}

// Download a certificate revocation list
func (c App) DownloadCRL(crlId int) revel.Result {
	obj, err := c.Txn.Get(models.CACount{}, crlId)
	if err != nil {
		c.Flash.Error("CA CRL not found")
		return c.Redirect(routes.App.Index())
	}
	crl := obj.(*models.CACount)
	revel.INFO.Println(crl)

	var signKey interface{}

	// Getting signed by CA, get CA private key bytes
	var ca_bytes []byte
	ca_block, _ := pem.Decode(crl.Certificate.PrivateKey)
	if ca_block == nil {
		c.Flash.Error("Unable to decode CA privatekey")
		return c.Redirect(routes.App.Index())
	}
	ca_bytes = ca_block.Bytes
	/* For now assume unencrypted
	if x509.IsEncryptedPEMBlock(ca_block) {
		if len(certificate.CAEncryptionKey) == 0 {
			return nil, errors.New("Unable to unlock CA key")
		} else {
			// CA is encrypted so decrypt it
			ca_bytes, err = x509.DecryptPEMBlock(ca_block, []byte(certificate.CAEncryptionKey))
			if err != nil {
				return nil, errors.New("Unable to decrypt CA key")
			}
		}
	}
	*/

	// Obtain the key for the CA for signing
	if crl.Certificate.KeyType == models.RSA {
		signKey, err = x509.ParsePKCS1PrivateKey(ca_bytes)
		if err != nil {
			c.Flash.Error("Error parsing certificate")
			return c.Redirect(routes.App.Index())
		}

	} else {
		signKey, err = x509.ParseECPrivateKey(ca_bytes)
		if err != nil {
			c.Flash.Error("Error parsing certificate")
			return c.Redirect(routes.App.Index())
		}
	}

	// We need the public certificate of the CA as well
	block, _ := pem.Decode(crl.Certificate.PEM)
	if block == nil {
		c.Flash.Error("Unable to decode CA Cert")
		return c.Redirect(routes.App.Index())
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Flash.Error("Error parsing certificate")
		return c.Redirect(routes.App.Index())
	}

	all_revoked := c.getAllRevokedCerts()
	revoked := make([]pkix.RevokedCertificate, len(all_revoked))
	for i, r := range all_revoked {
		revoked[i] = pkix.RevokedCertificate{SerialNumber: big.NewInt(int64(r.Certificate.SerialNumber)), RevocationTime: time.Now()}
	}

	x509Cert := x509Certificate(*cert)
	revokedBytes, err := x509Cert.CreateCRL(rand.Reader, signKey, revoked, time.Now(), time.Now())
	if err != nil {
		c.Flash.Error("Error creating CRL")
		return c.Redirect(routes.App.Index())
	}

	pemCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revokedBytes})

	return Download(string(pemCRL))
}
