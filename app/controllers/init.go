package controllers

import (
	"bytes"
	"github.com/robfig/revel"
	"html/template"
	"math/rand"
	"strings"
	"time"
)

func init() {

	// Seed the random library
	rand.Seed(time.Now().UTC().UnixNano())

	revel.OnAppStart(Init)
	revel.InterceptMethod((*GorpController).Begin, revel.BEFORE)
	//revel.InterceptMethod(Application.AddUser, revel.BEFORE)
	revel.InterceptMethod(App.AddUser, revel.BEFORE)
	revel.InterceptMethod(App.logEntry, revel.BEFORE)
	//revel.InterceptMethod(Hotels.checkUser, revel.BEFORE)
	revel.InterceptMethod((*GorpController).Commit, revel.AFTER)
	revel.InterceptMethod((*GorpController).Rollback, revel.FINALLY)

	revel.TemplateFuncs["countryOption"] = getCountryOptions
	revel.TemplateFuncs["keyOption"] = getKeyOptions
	revel.TemplateFuncs["keyUsageOption"] = getKeyUsageOptions
	revel.TemplateFuncs["extKeyUsageOption"] = getExtKeyUsageOptions
}

var countryList = []string{"AF", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD", "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CY", "CZ", "DK", "DJ", "DM", "DO", "TP", "EC", "EG", "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "FX", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GN", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IL", "IT", "JM", "JP", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "AN", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "KN", "LC", "VC", "WS", "SM", "ST", "SA", "SN", "SC", "SL", "SG", "SK", "SI", "SB", "SO", "ZA", "GS", "ES", "LK", "SH", "PM", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "YU", "ZM", "ZW"}
var countryMap = map[string]string{"AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegowina", "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil", "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Congo, the Democratic Republic of the", "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote d'Ivoire", "HR": "Croatia (Hrvatska)", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "TP": "East Timor", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland", "FR": "France", "FX": "France, Metropolitan", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti", "HM": "Heard and Mc Donald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran (Islamic Republic of)", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "KP": "Korea, Democratic People's Republic of", "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libyan Arab Jamahiriya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau", "MK": "Macedonia, The Former Yugoslav Republic of", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of", "MC": "Monaco", "MN": "Mongolia", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "AN": "Netherlands Antilles", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RE": "Reunion", "RO": "Romania", "RU": "Russian Federation", "RW": "Rwanda", "KN": "Saint Kitts and Nevis", "LC": "Saint LUCIA", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia (Slovak Republic)", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands", "ES": "Spain", "LK": "Sri Lanka", "SH": "St. Helena", "PM": "St. Pierre and Miquelon", "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen Islands", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland", "SY": "Syrian Arab Republic", "TW": "Taiwan, Province of China", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of", "TH": "Thailand", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Viet Nam", "VG": "Virgin Islands (British)", "VI": "Virgin Islands (U.S.)", "WF": "Wallis and Futuna Islands", "EH": "Western Sahara", "YE": "Yemen", "YU": "Yugoslavia", "ZM": "Zambia", "ZW": "Zimbabwe"}

// Function available to templates to fill country dropdown
func getCountryOptions(selectedCountry string) template.HTML {
	option_tmpl := "<option value=\"{{.Abbreviation}}\" {{if.Selected}}selected=\"{{.Selected}}\"{{end}}>{{.Country}}</option>"
	t := template.Must(template.New("option").Parse(option_tmpl))
	type countryOption struct {
		Abbreviation string
		Country      string
		Selected     string
	}
	output := ""
	for _, abbr := range countryList {
		selected := ""
		if selectedCountry == abbr {
			selected = "selected"
		}
		buff := bytes.NewBufferString("")
		err := t.Execute(buff, countryOption{Abbreviation: abbr, Country: countryMap[abbr], Selected: selected})
		if err != nil {

		}
		output += buff.String()
	}
	return template.HTML(output)
}

var keyList = []string{"RSA 1024", "RSA 2048", "RSA 4096", "ECDSA 224", "ECDSA 256"} //, "ECDSA 384", "ECDSA 521"

// Function available to templates to fill Certificate Key Type dropdown
func getKeyOptions(selectedOption string) template.HTML {
	option_tmpl := "<option value=\"{{.Key}}\" {{if.Selected}}selected=\"{{.Selected}}\"{{end}}>{{.Key}}</option>"
	t := template.Must(template.New("option").Parse(option_tmpl))
	type keyOption struct {
		Place    int
		Key      string
		Selected string
	}
	output := ""
	for place, key := range keyList {
		selected := ""
		if selectedOption == key {
			selected = "selected"
		}
		buff := bytes.NewBufferString("")
		err := t.Execute(buff, keyOption{Place: place, Key: key, Selected: selected})
		if err != nil {

		}
		output += buff.String()
	}
	return template.HTML(output)
}

var keyUsageList = []string{"1", "2", "4", "8", "16", "32", "64", "128", "256"}
var keyUsageMap = map[string]string{"1": "Digital Signature", "2": "Content Commitment", "4": "Key Encipherment", "8": "Data Encipherment", "16": "Key Agreement", "32": "Cert Sign", "64": "CRL Sign", "128": "Encipher Only", "256": "Decipher Only"}

// Function available to templats to fill Certificate Key Usage dropdown
func getKeyUsageOptions(selectedKeys string) template.HTML {
	option_tmpl := "<option value=\"{{.Value}}\" {{if.Selected}}selected=\"{{.Selected}}\"{{end}}>{{.KeyUsage}}</option>"
	t := template.Must(template.New("option").Parse(option_tmpl))
	type keyUsageOption struct {
		Value    string
		KeyUsage string
		Selected string
	}
	output := ""
	for _, value := range keyUsageList {
		selected := ""
		if strings.Contains(selectedKeys, value) {
			selected = "selected"
		}
		buff := bytes.NewBufferString("")
		err := t.Execute(buff, keyUsageOption{Value: value, KeyUsage: keyUsageMap[value], Selected: selected})
		if err != nil {

		}
		output += buff.String()
	}
	return template.HTML(output)
}

var extKeyUsageList = []string{"0", "1", "2", "3", "4", "8", "9"}
var extKeyUsageMap = map[string]string{"0": "Any", "1": "Server Authentication", "2": "Client Authentication", "3": "Code Signing", "4": "Email Protection", "8": "Time Stamping", "9": "OCSP Signing"}

// Function available to templats to fill Certificate Extra Key Usage dropdown
func getExtKeyUsageOptions(selectedKeys string) template.HTML {
	option_tmpl := "<option value=\"{{.Value}}\" {{if.Selected}}selected=\"{{.Selected}}\"{{end}}>{{.KeyUsage}}</option>"
	t := template.Must(template.New("option").Parse(option_tmpl))
	type keyUsageOption struct {
		Value    string
		KeyUsage string
		Selected string
	}
	output := ""
	for _, value := range extKeyUsageList {
		selected := ""
		if strings.Contains(selectedKeys, value) {
			selected = "selected"
		}
		buff := bytes.NewBufferString("")
		err := t.Execute(buff, keyUsageOption{Value: value, KeyUsage: extKeyUsageMap[value], Selected: selected})
		if err != nil {

		}
		output += buff.String()
	}
	return template.HTML(output)
}
