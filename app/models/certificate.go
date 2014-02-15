package models

import (
	"fmt"
	//"github.com/robfig/revel"
	"github.com/coopernurse/gorp"
)

// The Full data associated with a certificate
type FullCertificate struct {
	Country, State, City           string
	Organization, OrganizationUnit string
	CommonName                     string
	Expires                        string
	PrivateKeyType                 string
	IsCA                           bool
	KeyUses, ExtKeyUses            []string
	SignedBy                       int

	EncryptionKey   string
	CAEncryptionKey string
}

// Types of Key used
type KeyType int

const (
	RSA KeyType = iota
	ECDSA
)

// Certificate model as stored in the database
type Certificate struct {
	// Unique ID
	Id int
	// PEM and Private key as can be written to file
	PEM, PrivateKey []byte
	// The x509 CN of the certificate
	CommonName string
	// The type of key used
	KeyType

	SerialNumber int

	// Whether the certificate represents a CA, and whether the key is encrypted
	CA, Encrypted bool

	// The ID of the project this cert is associated with
	ProjectId int

	// The Project this cert is associated with
	Project *Project
}

// Model for CAs to keep track of which serial number was last issued
type CACount struct {
	// Unique ID
	Id int

	// The CA cert
	CertificateId int
	Certificate   *Certificate

	// Last Serial number used
	SerialNumber int
}

// Certificate template model as stored in the database
type CertificateTemplate struct {
	// Unique ID
	Id   int
	Name string

	Country, State, City           string
	Organization, OrganizationUnit string
	Expires                        string
	PrivateKeyType                 string
	IsCA                           bool
	KeyUses, ExtKeyUses            string
	SignedBy                       int

	// The ID of the project this cert is associated with
	ProjectId int

	// The Project this cert is associated with
	Project *Project
}

// Certificate model as stored in the database
type CertificateRequest struct {
	// Unique ID
	Id int
	// PEM and Private key as can be written to file
	CSR []byte

	// The ID of the Certificate requested to be signed by
	RequestedCAId int
	// The Certificate requested to be signed by
	RequestedCA *Certificate

	// The ID of the project this cert is associated with
	ProjectId int

	// The Project this cert is associated with
	Project *Project

	// The user that submitted the CSR
	UserId int
	User   *User
}

// Join a certificate to the user that owns it
type CertificateOwnership struct {
	Id                    int
	CertificateId, UserId int

	Certificate *Certificate
	User        *User
}

// Represents a One Time link to download a key
type CertificateOneTimeDownload struct {
	Id            int
	CertificateId int
	Hash          string

	Certificate *Certificate
}

// Represents a revoked certificate, used to generate
type RevokedCertificate struct {
	Id            int
	CertificateId int

	Certificate *Certificate
}

// Before inserting a cert into the db, make sure that ProjectId is set
func (c *Certificate) PreInsert(_ gorp.SqlExecutor) error {
	if c.Project != nil {
		c.ProjectId = c.Project.Id
	}

	return nil
}

// After get a cert from the db, set the project based on the ProjectId
func (c *Certificate) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.ProjectId != 0 {
		obj, err = exe.Get(Project{}, c.ProjectId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate's project (%d): %s", c.ProjectId, err)
		}
		c.Project = obj.(*Project)
	}

	return nil
}

// Before inserting a template into the db, make sure that ProjectId is set
func (c *CertificateTemplate) PreInsert(_ gorp.SqlExecutor) error {
	if c.Project != nil {
		c.ProjectId = c.Project.Id
	}

	return nil
}

// After getting a template from the db, set the project based on the ProjectId
func (c *CertificateTemplate) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.ProjectId != 0 {
		obj, err = exe.Get(Project{}, c.ProjectId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate's project (%d): %s", c.ProjectId, err)
		}
		c.Project = obj.(*Project)
	}

	return nil
}

// Before inserting a certificate request into the db, make sure that ProjectId and RequestedCAID are set
func (c *CertificateRequest) PreInsert(_ gorp.SqlExecutor) error {
	if c.Project != nil {
		c.ProjectId = c.Project.Id
	}
	if c.RequestedCA != nil {
		c.RequestedCAId = c.RequestedCA.Id
	}
	if c.User != nil {
		c.UserId = c.User.Id
	}

	return nil
}

// After getting a template from the db, set the project based on the ProjectId and RequestedCAID
func (c *CertificateRequest) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.ProjectId != 0 {
		obj, err = exe.Get(Project{}, c.ProjectId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate's project (%d): %s", c.ProjectId, err)
		}
		c.Project = obj.(*Project)
	}

	if c.RequestedCAId != 0 {
		obj, err = exe.Get(Certificate{}, c.RequestedCAId)
		if err != nil {
			return fmt.Errorf("Error loading a csr's requested CA (%d): %s", c.RequestedCAId, err)
		}
		c.RequestedCA = obj.(*Certificate)
	}

	if c.UserId != 0 {
		obj, err = exe.Get(User{}, c.UserId)
		if err != nil {
			return fmt.Errorf("Error loading a csr's requesting user (%d): %s", c.UserId, err)
		}
		c.User = obj.(*User)
	}

	return nil
}

// Before inserting a cert ownership into the db, make sure that userID and CertificateId are set
func (c *CertificateOwnership) PreInsert(_ gorp.SqlExecutor) error {
	if c.User != nil {
		c.UserId = c.User.Id
	}

	if c.Certificate != nil {
		c.CertificateId = c.Certificate.Id
	}

	return nil
}

// After getting certificate ownership, set Certificate and User
func (c *CertificateOwnership) PostGet(exe gorp.SqlExecutor) error {
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

	if c.CertificateId != 0 {
		obj, err = exe.Get(Certificate{}, c.CertificateId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate (%d): %s", c.CertificateId, err)
		}
		c.Certificate = obj.(*Certificate)
	}

	return nil
}

// Before inserting a certOneTimeDownload into the db, make sure that CertificateId is set
func (c *CertificateOneTimeDownload) PreInsert(_ gorp.SqlExecutor) error {

	if c.Certificate != nil {
		c.CertificateId = c.Certificate.Id
	}

	return nil
}

// After getting CertOneTimeDownload from db, set Certificate
func (c *CertificateOneTimeDownload) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.CertificateId != 0 {
		obj, err = exe.Get(Certificate{}, c.CertificateId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate (%d): %s", c.CertificateId, err)
		}
		c.Certificate = obj.(*Certificate)
	}

	return nil
}

// Before inserting a Revoked Certificate into the db, make sure that CertificateId is set
func (c *RevokedCertificate) PreInsert(_ gorp.SqlExecutor) error {

	if c.Certificate != nil {
		c.CertificateId = c.Certificate.Id
	}

	return nil
}

// After getting a Revoked Certificate from db, set Certificate
func (c *RevokedCertificate) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.CertificateId != 0 {
		obj, err = exe.Get(Certificate{}, c.CertificateId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate (%d): %s", c.CertificateId, err)
		}
		c.Certificate = obj.(*Certificate)
	}

	return nil
}

// Before inserting a Revoked Certificate into the db, make sure that CertificateId is set
func (c *CACount) PreInsert(_ gorp.SqlExecutor) error {

	if c.Certificate != nil {
		c.CertificateId = c.Certificate.Id
	}

	return nil
}

// After getting a Revoked Certificate from db, set Certificate
func (c *CACount) PostGet(exe gorp.SqlExecutor) error {
	var (
		obj interface{}
		err error
	)

	if c.CertificateId != 0 {
		obj, err = exe.Get(Certificate{}, c.CertificateId)
		if err != nil {
			return fmt.Errorf("Error loading a certificate (%d): %s", c.CertificateId, err)
		}
		c.Certificate = obj.(*Certificate)
	}

	return nil
}
