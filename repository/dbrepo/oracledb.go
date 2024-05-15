package dbrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tijanadmi/works_api/models"
	"golang.org/x/crypto/bcrypt"
)

type OracleDBRepo struct {
	DB *sql.DB
}

func (m *OracleDBRepo) Connection() *sql.DB {
	return m.DB
}

func (m *OracleDBRepo) GetPermissions1(year string) ([]*models.Permission, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `select RBR_PK,
				BR_ZAHTEVA_FK,
				SAP_SIFRA,
				BROJ_ISK,
				BR_DOZVOLE,
				TIP_RADOVA,
				EE_OBJEKAT,
				TIP,
				OZNAKA,
				STATUS_EL,
				IZUZEV,
				NAPOMENA,
				DOZ_IZDAO,
				DOZ_PRIMIO,
				DAT_PRIJEMA_DOZ,
				VREME_PRIJEMA_DOZ,
				STASTUS_DOZ,
				NAPOMENA_ZAV_RAD,
				DOZ_ZAV_IZDAO,
				DOZ_ZAV_PRIMIO,
				DAT_ZAV_RADOVA,
				VREME_ZAV_RAD
			  from dozvole_1 where substr(dat_prijema_doz,length(dat_prijema_doz)-3,4) = :1
			  or  substr(dat_zav_radova,length(dat_zav_radova)-3,4)= :2`

	rows, err := m.DB.QueryContext(ctx, query, year, year)
	if err != nil {
		fmt.Println("Pogresan upit ili nema rezultata upita")
		return nil, err
	}
	defer rows.Close()

	var permissions []*models.Permission

	for rows.Next() {
		var data models.Permission
		err := rows.Scan(
			&data.RbrPk,
			&data.BrZahtevaFK,
			&data.SapSifra,
			&data.BrojIsk,
			&data.BrDozvole,
			&data.TipRadova,
			&data.EeObjekat,
			&data.Tip,
			&data.Oznaka,
			&data.StatusEl,
			&data.Izuzev,
			&data.Napomena,
			&data.DozIzdao,
			&data.DozPrimio,
			&data.DatPrijemaDoz,
			&data.VremePrijemaDoz,
			&data.StatusDoz,
			&data.NapomenaZavRad,
			&data.DozZavIzdao,
			&data.DozZavPrimio,
			&data.DatZavRadova,
			&data.VremeZavRad,
		)

		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &data)
	}

	return permissions, nil
}

func (m *OracleDBRepo) GetPlans(year string) ([]*models.Plan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `select COALESCE(to_char(ID_POG_ODR), ''),
				ID_SAP_F_LOK,
				ID_IPS_F_LOK,
				OPIS,
				COALESCE(to_char(ID_POG_PLAN), ''),
				COALESCE(to_char(PL_ODR), ''),
				TKS_ST_OD,
				TIP_NALOGA,
				to_char(DATUM_POC,'dd.mm.yyyy'),
				to_char(DATUM_ZAV,'dd.mm.yyyy'),
				COALESCE(to_char(ID), '')
				from PLAN_O_VNP_V
				where to_char(DATUM_POC,'yyyy')= :1
				or to_char(DATUM_ZAV,'dd.mm.yyyy')= :2`

	rows, err := m.DB.QueryContext(ctx, query, year, year)
	if err != nil {
		fmt.Println("Pogresan upit ili nema rezultata upita")
		return nil, err
	}
	defer rows.Close()

	var p []*models.Plan

	for rows.Next() {
		var data models.Plan
		err := rows.Scan(
			&data.IdPogOdr,
			&data.IdSapFLok,
			&data.IdIPSFLok,
			&data.Opis,
			&data.IdPogPlan,
			&data.PlOdr,
			&data.TksStOd,
			&data.TipNaloga,
			&data.DatumPoc,
			&data.DatumZav,
			&data.Id,
		)

		if err != nil {
			return nil, err
		}

		p = append(p, &data)
	}

	return p, nil
}

// Authenticate authenticates a user
func (m *OracleDBRepo) Authenticate(username, testPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	/*var id int
	var hashedPassword string*/

	var user models.User

	query := `select id, username, password from tis_services_users where username = :1`

	row := m.DB.QueryRowContext(ctx, query, username)
	err := row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(testPassword))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return errors.New("incorrect password")
	} else if err != nil {
		return err
	}
	return nil
}

func (m *OracleDBRepo) GetUserByUsername(username string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `select id, username, password from tis_services_users where username = :1`

	var user models.User
	row := m.DB.QueryRowContext(ctx, query, username)

	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
	)

	if err != nil {
		return nil, err
	}
	query = `select ru.id,RU.ID_USER, RU.ID_ROLE, R.CODE, R.NAME
	from tis_services_role_user ru, tis_services_roles r
	where RU.ID_USER =:1
	and ru.id_role = r.id
	`

	var roles []models.UserRole
	rows, _ := m.DB.QueryContext(ctx, query, user.ID)
	defer rows.Close()

	for rows.Next() {
		var r models.UserRole
		err := rows.Scan(
			&r.ID,
			&r.IdUser,
			&r.IdRole,
			&r.RoleCode,
			&r.RoleName,
		)

		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	user.UserRole = roles

	return &user, nil
}

func (m *OracleDBRepo) GetUserByID(id int) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `select id, username, password from tis_services_users where id = :1`

	var user models.User
	row := m.DB.QueryRowContext(ctx, query, id)

	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
	)

	if err != nil {
		return nil, err
	}

	query = `select ru.id,RU.ID_USER, RU.ID_ROLE, R.CODE, R.NAME
	from tis_services_role_user ru, tis_services_roles r
	where RU.ID_USER =:1
	and ru.id_role = r.id
	`

	var roles []models.UserRole
	rows, _ := m.DB.QueryContext(ctx, query, id)
	defer rows.Close()

	for rows.Next() {
		var r models.UserRole
		err := rows.Scan(
			&r.ID,
			&r.IdUser,
			&r.IdRole,
			&r.RoleCode,
			&r.RoleName,
		)

		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	user.UserRole = roles

	return &user, nil
}
