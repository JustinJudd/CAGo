package models

import (
	"fmt"
	"github.com/robfig/revel"
	"regexp"
	//"github.com/coopernurse/gorp"
)

// User model as stored in the database
type User struct {
	Id                       int
	Email                    string
	Username, Name, Password string // Password is not stored in the DB
	HashedPassword           []byte
	IsAdmin                  bool
}

func (u *User) String() string {
	return fmt.Sprintf("User(%s), Email(%s)", u.Username, u.Email)
}

var userRegex = regexp.MustCompile("^\\w*$")

func (user *User) Validate(v *revel.Validation) {

	/*
		v.Check(user.Username,
			revel.Required{},
			revel.Range{revel.Min{4},revel.Max{15}},
			revel.Match{userRegex},
		)

		v.Check(user.Email,
			revel.Required{},
			revel.MaxSize{50},
			revel.MinSize{4},

			//revel.Match{revel.emailPattern},
		).Message("Email")

		ValidatePassword(v, user.Password).
			Key("user.Password")

		v.Check(user.Name,
			revel.Required{},
			revel.MaxSize{100},
		)
	*/

	v.Required(user.Username)
	v.MinSize(user.Username, 6).Message("Username must be at least 6 characters")

	v.Required(user.Name)
	v.MinSize(user.Name, 2).Message("Name must be at least 2 characters")

	v.Required(user.Email)
	v.Email(user.Email)
	v.MinSize(user.Email, 5)

	/*
		v.Required(user.Password)
		v.MinSize(user.Password, 8).Message("Password must be at least 8 characters")
	*/

}

/*
func ValidatePassword(v *revel.Validation, password string) *revel.ValidationResult {
	return v.Check(password,
		revel.Required{},
		revel.MaxSize{15},
		revel.MinSize{5},
	)
}
*/
