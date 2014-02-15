package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"github.com/JustinJudd/CAGo/app/routes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/robfig/revel"
	"math/big"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/go.crypto/bcrypt"
	"crypto"
	"errors"
	"io"
)

// Default controller struct for CA Go
type App struct {
	GorpController
}

// Struct to keep track of place within the site, for breadcrumb UI
type BreadCrumb struct {
	Name, Url string
	Active    bool
}

// This function is registered to be run before every controller function
func (c App) logEntry() revel.Result {
	revel.INFO.Println(c.Request.Method, c.Request.URL, "(Action:", c.Action, "Params:", c.Params.Route, "User:", c.Session["user"], ")")
	return nil
}

// Get a list of all of the users
func (c App) getUsers() []*models.User {
	users, err := c.Txn.Select(models.User{}, `select * from User`)
	if err != nil {
		panic(err)
	}
	if len(users) == 0 {
		return nil
	}
	users_list := make([]*models.User, len(users), len(users))
	for i, user := range users {
		users_list[i] = user.(*models.User)
	}
	return users_list
}

// Get a list of all projects the user owns
func (c App) getUserProjects(user *models.User) []*models.Project {
	projects, err := c.Txn.Select(models.Project{}, `select Project.* from Project, ProjectMembership where ProjectMembership.UserId = ? and ProjectMembership.ProjectId = Project.Id`, user.Id)
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

func (c App) getServerURL() string {
	s, err := c.Txn.SelectStr("select URL from server where Id=?", 1)
	if err != nil {
		panic(err)
	}
	return s
}

func (c App) getServerPort() string {
	config, err := revel.LoadConfig("app.conf")
	if err != nil || config == nil {
		panic(err)
	}
	httpPort := config.IntDefault("http.port", 9000)
	port := strconv.Itoa(httpPort)
	return port
}

/*
Main page of the site

Starts Tour if first time used, or Lists all of the available projects
*/
func (c App) Index() revel.Result {
	users := c.getUsers()
	if len(users) == 0 {
		return c.Redirect(routes.Tour.Index())
	}

	userId := 0
	if c.RenderArgs["user"] != nil {
		user := c.RenderArgs["user"].(*models.User)
		userId = user.Id
	}

	projects := c.getVisibleProjects(userId)

	return c.Render(projects)
}

// Display a page to register a new user
func (c App) Register() revel.Result {
	return c.Render()
}

// Wrapper to create and merge error messages with errors
func newError(message string, err error) error {
	return errors.New(message + ": " + err.Error())
}

func (c App) makeCRLLocation(crlId int) string {
	return c.getServerURL() + ":" + c.getServerPort() + routes.App.DownloadCRL(crlId)
}

// Base code to actually create and store a new certificate
// Return the id of the new certificate(or -1) and an error (or nil)
func (c App) createCertificate(id int, certificate models.FullCertificate) (*models.Certificate, error) {

	// Keep track of whether this is a self signed certificate
	var sign_cert *models.Certificate

	// Get the CA certificate that is signing this new cert
	var project *models.Project
	if id >= 0 {
		project = c.getProject(id)
		if project == nil {
			return nil, errors.New("Unable to retreive project")
		}
		cas := c.getProjectCAs(project)

		ca := c.Params.Values["certificate.SignedBy"][0]
		ca_val, _ := strconv.Atoi(ca)
		for _, c := range cas {
			if c.Id == ca_val {
				sign_cert = c
			}
		}
	}

	serialNumber := 1
	caCount := &models.CACount{}
	var CRLLocation []string
	if sign_cert != nil {
		// Another Cert is CA
		obj, err := c.Txn.Get(models.CACount{}, sign_cert.Id)
		if err != nil {
			return nil, errors.New("Error determining Serial Number")
		}
		caCount = obj.(*models.CACount)
		serialNumber = caCount.SerialNumber + 1
		caCount.SerialNumber = serialNumber
		_, err = c.Txn.Update(caCount)
		if err != nil {
			return nil, newError("Error saving ca count", err)
		}
		// Use the CRL of the cert that is signing it
		CRLLocation := []string{c.makeCRLLocation(caCount.Id)}
		if certificate.IsCA {
			// This certificate should now have it's own
			CRLLocation = append(CRLLocation, c.makeCRLLocation(caCount.Id))

		}
	} else {
		crlCount := c.getCRLCount()
		CRLLocation = []string{c.makeCRLLocation(crlCount + 1)}

	}

	// Set up ways Key can be used
	certificate.KeyUses = c.Params.Values["certificate.KeyUses"]
	certificate.ExtKeyUses = c.Params.Values["certificate.ExtKeyUses"]

	//Set up primary key uses
	keyUsage := 0
	for _, use := range certificate.KeyUses {
		v, _ := strconv.Atoi(use)
		keyUsage = keyUsage | v
	}
	// CAs need to be able to sign other certificates and Certificate Revocation Lists
	if certificate.IsCA {
		keyUsage = keyUsage | int(x509.KeyUsageCertSign) | int(x509.KeyUsageCRLSign)
	}

	// Set up extra key uses for certificate
	extKeyUsage := make([]x509.ExtKeyUsage, 0)
	for _, use := range certificate.ExtKeyUses {
		v, _ := strconv.Atoi(use)
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsage(v))
	}

	endTime, _ := time.Parse("2006-01-02", certificate.Expires)

	encrypted := false

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(serialNumber)),
		Subject: pkix.Name{
			Organization:       []string{certificate.Organization},
			OrganizationalUnit: []string{certificate.OrganizationUnit},
			Country:            []string{certificate.Country},
			Province:           []string{certificate.State},
			Locality:           []string{certificate.City},
			CommonName:         certificate.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              endTime,
		IsCA:                  certificate.IsCA,
		KeyUsage:              x509.KeyUsage(keyUsage),
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		CRLDistributionPoints: CRLLocation,
	}

	enc := strings.Split(certificate.PrivateKeyType, " ")
	var privCert []byte
	var pubCert []byte
	var keyType models.KeyType
	var signKey interface{}
	var parent *x509.Certificate

	// Create RSA Cert
	if strings.HasPrefix(enc[0], "RSA") {
		keyType = models.RSA
		size, err := strconv.Atoi(enc[1])
		if err != nil {
			return nil, newError("Failed to generate private key", err)
		}
		priv, err := rsa.GenerateKey(rand.Reader, size)

		if err != nil {
			return nil, newError("Failed to generate private key", err)
		}
		if sign_cert == nil {
			signKey = priv
			parent = &template
		} else {

			// Getting signed by CA, get CA private key bytes
			var ca_bytes []byte
			ca_block, _ := pem.Decode(sign_cert.PrivateKey)
			if ca_block == nil {
				return nil, newError("Unable to decode CA privatekey", nil)
			}
			ca_bytes = ca_block.Bytes
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

			// Obtain the key for the CA for signing
			if sign_cert.KeyType == models.RSA {
				signKey, err = x509.ParsePKCS1PrivateKey(ca_bytes)
				if err != nil {
					return nil, newError("Error parsing certificate", err)
				}

			} else {
				signKey, err = x509.ParseECPrivateKey(ca_bytes)
				if err != nil {
					return nil, newError("Error parsing certificate", err)
				}
			}

			// We need the public certificate of the CA as well
			block, _ := pem.Decode(sign_cert.PEM)
			if block == nil {
				return nil, newError("Unable to decode CA cert", nil)
			}
			parent, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, newError("Failed to generate private key:", err)
			}

		}
		pub := priv.PublicKey
		marshalledKey := x509.MarshalPKCS1PrivateKey(priv)
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &pub, signKey)
		if err != nil {
			return nil, newError("Failed to create certificate \n", err)
		}
		// Convert certificate to PEM to be stored in DB
		pubCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		pemKeyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marshalledKey}
		// Encrypt the private key if an encryption key was provided
		if len(certificate.EncryptionKey) > 0 {
			pemKeyBlock, err = x509.EncryptPEMBlock(rand.Reader, pemKeyBlock.Type, pemKeyBlock.Bytes, []byte(certificate.EncryptionKey), x509.PEMCipherAES256)
			if err != nil {
				return nil, newError("Failed to encrypt key", err)
			}
			encrypted = true
		}
		privCert = pem.EncodeToMemory(pemKeyBlock)

	} else { // Create ECDSA Cert

		keyType = models.ECDSA
		var curve elliptic.Curve
		// Select the Elliptic curve to use
		switch enc[1] {
		case "224":
			curve = elliptic.P224()

		case "256":
			curve = elliptic.P256()

		case "384":
			curve = elliptic.P384()

		case "521":
			curve = elliptic.P521()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		pub := priv.PublicKey
		if err != nil {
			return nil, newError("Failed to generate private key", err)
		}

		if sign_cert == nil {
			signKey = priv
			parent = &template
		} else {

			// Getting signed by CA, get CA private key bytes
			var ca_bytes []byte
			ca_block, _ := pem.Decode(sign_cert.PrivateKey)
			if ca_block == nil {
				return nil, newError("Unable to decode CA privatekey", nil)
			}
			ca_bytes = ca_block.Bytes
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

			// Obtain the key for the CA for signing
			if sign_cert.KeyType == models.RSA {
				signKey, err = x509.ParsePKCS1PrivateKey(ca_bytes)
				if err != nil {
					return nil, newError("Error parsing certificate", err)
				}

			} else {
				signKey, err = x509.ParseECPrivateKey(ca_bytes)
				if err != nil {
					return nil, newError("Error parsing certificate", err)
				}
			}

			// We need the public certificate of the CA as well
			block, _ := pem.Decode(sign_cert.PEM)
			if block == nil {
				return nil, newError("Unable to decode CA cert", nil)
			}
			parent, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, newError("Error parsing certificate", err)
			}

		}

		// All the parts to make a certificate are available
		// Create an x509 certificate
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &pub, signKey)
		if err != nil {
			return nil, newError("Failed to create certificate", err)
		}

		// Convert certificate to PEM to be stored in DB
		pubCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		//marshalledKey, err := MarshalECPrivateKey(priv)
		marshalledKey, err := x509.MarshalECPrivateKey(priv) // To be used for go 1.2 (added to default x509 lib)
		if err != nil {
			return nil, newError("Failed Marshal EC Private Key", err)
		}

		pemKeyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalledKey}
		if len(certificate.EncryptionKey) > 0 {
			pemKeyBlock, err = x509.EncryptPEMBlock(rand.Reader, pemKeyBlock.Type, pemKeyBlock.Bytes, []byte(certificate.EncryptionKey), x509.PEMCipherAES256)
			if err != nil {
				return nil, newError("Failed to encrypt key", err)
			}
			encrypted = true
		}
		privCert = pem.EncodeToMemory(pemKeyBlock)
	}

	// Create Certificate model for certificate table
	cert := models.Certificate{PEM: pubCert, PrivateKey: privCert, CommonName: certificate.CommonName, CA: certificate.IsCA, Project: project, KeyType: keyType, Encrypted: encrypted, SerialNumber: serialNumber}

	// Save the certificate in the database
	err := c.Txn.Insert(&cert)
	if err != nil {
		return nil, newError("Error saving certificate", err)
	}

	if sign_cert == nil {
		// Cert is self signed
		caCount.SerialNumber = serialNumber
		caCount.Certificate = &cert

		err := c.Txn.Insert(caCount)
		if err != nil {
			return nil, newError("Error saving ca count", err)
		}
	}

	return &cert, nil
}

// Create and save the new user
func (c App) saveUser(user models.User, verifyPassword string) error {

	// Validate the user, make sure passwords are valid ...
	c.Validation.Required(verifyPassword)
	c.Validation.Required(verifyPassword == user.Password).
		Message("Password does not match")
	user.Validate(c.Validation)

	if c.Validation.HasErrors() {
		c.Validation.Keep()
		c.FlashParams()
		return errors.New("Unable to validate input")
	}

	user.HashedPassword, _ = bcrypt.GenerateFromPassword(
		[]byte(user.Password), bcrypt.DefaultCost)

	// Insert the new user into the database
	err := c.Txn.Insert(&user)
	if err != nil {
		return newError("Unable to save user in database", err)
	}

	return nil
}

// Create and save a project and store it in database
func (c App) saveProject(project models.Project) error {

	// Save a project into the database
	err := c.Txn.Insert(&project)
	if err != nil {
		return newError("Unable to insert project into database", err)
	}

	// Add the creator as a project owner and save in database
	project_member := models.ProjectMembership{User: c.connected(), Project: &project, Admin: true}
	err = c.Txn.Insert(&project_member)
	if err != nil {
		return newError("Unable to create project membership", err)
	}

	return nil
}

/*
CSR - Certificate Signing Request as detailed in http://tools.ietf.org/html/rfc2986#section-4
This represents the ASN.1 format for a certificate request
*/
type certificationRequest struct {
	Raw                      asn1.RawContent
	CertificationRequestInfo certificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	SignatureValue           asn1.BitString
}

// Certificate Request Info ASN.1 representation, substruct for Certifificate Request
type certificationRequestInfo struct {
	Raw        asn1.RawContent
	Version    int `asn1:"default:1"`
	Subject    asn1.RawValue
	PublicKey  publicKeyInfo
	Attributes []pkix.AttributeTypeAndValue `asn1:"optional,tag:0"`
}

// Public Key Info ASN.1 representation, substruct for Certifificate Request
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Parse a certification request out of ASN.1 format
func ParseCertificationRequest(asn1Data []byte) (certificationRequest, error) {
	var csr certificationRequest
	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return csr, err
	}
	if len(rest) > 0 {
		return csr, errors.New("ASN1 trailing data")
	}

	return csr, nil
}

type x509Certificate x509.Certificate

func (c *x509Certificate) CreateCRL(rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {

	var signatureAlgorithm pkix.AlgorithmIdentifier
	var hashFunc crypto.Hash

	switch priv := priv.(type) {

	// CRL signing for RSA Keys is already in x509 lib
	case *rsa.PrivateKey:
		return c.CreateCRL(rand, priv, revokedCerts, now, expiry)

	case *ecdsa.PrivateKey:
		switch priv.Curve {

		case elliptic.P224(), elliptic.P256():
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
			hashFunc = crypto.SHA256

		case elliptic.P384():
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA384
			hashFunc = crypto.SHA384

		case elliptic.P521():
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA512
			hashFunc = crypto.SHA512

		default:
			return nil, errors.New("Unknown curve")
		}

	default:
		return nil, errors.New("Unknown key type")

	}

	tbsCertList := pkix.TBSCertificateList{
		Version:             2,
		Signature:           signatureAlgorithm,
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCerts,
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	h := hashFunc.New()
	h.Write(tbsCertListContents)
	digest := h.Sum(nil)

	var signature []byte

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand, priv, hashFunc, digest)
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand, priv, digest); err == nil {
			signature, err = asn1.Marshal(ecdsaSignature{r, s})
		}
	default:
		return nil, errors.New("Unknown key type")
	}

	if err != nil {
		return
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})

}

// Imported from cryto/x509 lib
var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

type ecdsaSignature struct {
	R, S *big.Int
}
