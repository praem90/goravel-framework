package auth

import (
	"fmt"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/foundation"
	"gorm.io/gorm/clause"
)

type OrmUserProvider struct {
    orm orm.Orm;
    model any
}

// RetriveByCredentials implements auth.UserProvider.
func (o OrmUserProvider) RetriveByCredentials(credentials map[string]any) any {
	panic("unimplemented")
}

// RetriveById implements auth.UserProvider.
func (o OrmUserProvider) RetriveById(id any) (any, error) {
	if err := o.orm.Query().FindOrFail(o.model, clause.Eq{Column: clause.PrimaryColumn, Value: id}); err != nil {
        return nil, err
    }

    return o.model, nil
}

func NewOrmUserProvider(app foundation.Application, config config.Config) contractsauth.UserProvider {
    model := config.Get(fmt.Sprintf("auth.providers.%s.model", "orm"))

    if model == nil {
        return nil
    }

	return OrmUserProvider{
        orm: app.MakeOrm(),
        model: model,
    }
}
