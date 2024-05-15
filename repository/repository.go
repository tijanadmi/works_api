package repository

import (
	"database/sql"

	"github.com/tijanadmi/works_api/models"
)

type DatabaseRepo interface {
	Connection() *sql.DB
	Authenticate(username, testPassword string) error
	GetUserByUsername(username string) (*models.User, error)
	GetUserByID(id int) (*models.User, error)
	GetPermissions1(year string) ([]*models.Permission, error)
	GetPlans(year string) ([]*models.Plan, error)
}
