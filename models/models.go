package models

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// Models is the wrapper for database
/*type Models struct {
	DB OracleDBRepo
}*/

// NewModels returns models with db pool
/*func NewModels(db *sql.DB) Models {
	return Models{
		DB: OracleDBRepo{DB: db},
	}
}*/

type Permission struct {
	RbrPk           int64  `json:"rbr_pk"`
	BrZahtevaFK     int64  `json:"br_zahteva_fk"`
	SapSifra        string `json:"sap_sifra"`
	BrojIsk         string `json:"broj_isk"`
	BrDozvole       string `json:"br_dozvole"`
	TipRadova       string `json:"tip_radova"`
	EeObjekat       string `json:"ee_objekat"`
	Tip             string `json:"tip"`
	Oznaka          string `json:"oznaka"`
	StatusEl        string `json:"status_el"`
	Izuzev          string `json:"izuzev"`
	Napomena        string `json:"napomena"`
	DozIzdao        string `json:"doz_izdao"`
	DozPrimio       string `json:"doz_primio"`
	DatPrijemaDoz   string `json:"dat_prijema_doz"`
	VremePrijemaDoz string `json:"vreme_prijema_doz"`
	StatusDoz       string `json:"status_doz"`
	NapomenaZavRad  string `json:"napomena_zav_rad"`
	DozZavIzdao     string `json:"doz_zav_izdao"`
	DozZavPrimio    string `json:"doz_zav_primio"`
	DatZavRadova    string `json:"dat_zav_radova"`
	VremeZavRad     string `json:"vreme_zav_rad"`
}

type Plan struct {
	IdPogOdr  string `json:"pog_odr_id"`
	IdSapFLok string `json:"sap_id"`
	IdIPSFLok string `json:"ips_id"`
	Opis      string `json:"opis"`
	IdPogPlan string `json:"id_pog_plan"`
	PlOdr     string `json:"pl_odr"`
	TksStOd   string `json:"tks_st_od"`
	TipNaloga string `json:"tip_naloga"`
	DatumPoc  string `json:"datum_poc"`
	DatumZav  string `json:"datum_zav"`
	Id        string `json:"id"`
}

// User is the type for users
type User struct {
	ID       int
	Username string
	Password string
	UserRole []UserRole
}

type Role struct {
	ID   int
	Code string
	Name string
}
type UserRole struct {
	ID       int
	IdUser   int
	IdRole   int
	RoleCode string
	RoleName string
}

func (u *User) PasswordMatches(plainText string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			// invalid password
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}
