package controllers

import (
	"github.com/JustinJudd/CAGo/app/models"
	"database/sql"
	"github.com/coopernurse/gorp"
	_ "github.com/mattn/go-sqlite3"
	r "github.com/robfig/revel"
	"github.com/robfig/revel/modules/db/app"
)

var (
	// Database Map
	Dbm *gorp.DbMap
)

// Initialize database and tables
func Init() {
	db.Init()
	Dbm = &gorp.DbMap{Db: db.Db, Dialect: gorp.SqliteDialect{}}

	setColumnSizes := func(t *gorp.TableMap, colSizes map[string]int) {
		for col, size := range colSizes {
			t.ColMap(col).MaxSize = size
		}
	}

	t := Dbm.AddTable(models.User{}).SetKeys(true, "Id")
	t.ColMap("Password").Transient = true
	setColumnSizes(t, map[string]int{
		"Email":    50,
		"Username": 100,
		"Name":     100,
	})

	t = Dbm.AddTable(models.Project{}).SetKeys(true, "Id")
	setColumnSizes(t, map[string]int{
		"Name":        100,
		"Description": 10240,
	})

	t = Dbm.AddTable(models.Certificate{}).SetKeys(true, "Id")
	t.ColMap("Project").Transient = true

	t = Dbm.AddTable(models.CertificateTemplate{}).SetKeys(true, "Id")
	t.ColMap("Project").Transient = true

	t = Dbm.AddTable(models.CertificateOwnership{}).SetKeys(true, "Id")
	t.ColMap("Certificate").Transient = true
	t.ColMap("User").Transient = true

	t = Dbm.AddTable(models.CertificateOneTimeDownload{}).SetKeys(true, "Id")
	t.ColMap("Certificate").Transient = true

	t = Dbm.AddTable(models.RevokedCertificate{}).SetKeys(true, "Id")
	t.ColMap("Certificate").Transient = true

	t = Dbm.AddTable(models.ProjectMembership{}).SetKeys(true, "Id")
	t.ColMap("Project").Transient = true
	t.ColMap("User").Transient = true

	t = Dbm.AddTable(models.CertificateRequest{}).SetKeys(true, "Id")
	t.ColMap("Project").Transient = true
	t.ColMap("RequestedCA").Transient = true
	t.ColMap("User").Transient = true

	t = Dbm.AddTable(models.CACount{}).SetKeys(true, "Id")
	t.ColMap("Certificate").Transient = true

	t = Dbm.AddTable(models.Server{}).SetKeys(true, "Id")

	//Dbm.TraceOn("[gorp]", r.INFO)
	Dbm.CreateTablesIfNotExists()

}

// Controller wrapping around database operations - Foundation for app controller
type GorpController struct {
	*r.Controller
	Txn *gorp.Transaction
}

// Begin database transaction
func (c *GorpController) Begin() r.Result {
	txn, err := Dbm.Begin()
	if err != nil {
		panic(err)
	}
	c.Txn = txn
	return nil
}

// Commit database transaction
func (c *GorpController) Commit() r.Result {
	if c.Txn == nil {
		return nil
	}
	if err := c.Txn.Commit(); err != nil && err != sql.ErrTxDone {
		panic(err)
	}
	c.Txn = nil
	return nil
}

// Rollback a database transaction
func (c *GorpController) Rollback() r.Result {
	if c.Txn == nil {
		return nil
	}
	if err := c.Txn.Rollback(); err != nil && err != sql.ErrTxDone {
		panic(err)
	}
	c.Txn = nil
	return nil
}

// Add table for Certificates
func (c *GorpController) AddCertTable(tableName string) {
	t := Dbm.AddTableWithName(models.Certificate{}, tableName).SetKeys(true, "Id")
	t.ColMap("User").Transient = true
}
