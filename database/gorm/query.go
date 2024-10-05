package gorm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"

	"github.com/spf13/cast"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	gormio "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/goravel/framework/contracts/config"
	contractsdatabase "github.com/goravel/framework/contracts/database"
	contractsorm "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/log"
	"github.com/goravel/framework/database/db"
	"github.com/goravel/framework/database/gorm/hints"
	"github.com/goravel/framework/database/orm"
	"github.com/goravel/framework/support/database"
)

type Query struct {
	conditions Conditions
	config     config.Config
	ctx        context.Context
	fullConfig contractsdatabase.FullConfig
	instance   *gormio.DB
	log        log.Log
	queries    map[string]*Query
}

func NewQuery(ctx context.Context, config config.Config, fullConfig contractsdatabase.FullConfig, db *gormio.DB, log log.Log, conditions *Conditions) *Query {
	queryImpl := &Query{
		config:     config,
		ctx:        ctx,
		fullConfig: fullConfig,
		instance:   db,
		log:        log,
		queries:    make(map[string]*Query),
	}

	if conditions != nil {
		queryImpl.conditions = *conditions
	}

	return queryImpl
}

func BuildQuery(ctx context.Context, config config.Config, connection string, log log.Log) (*Query, error) {
	configBuilder := db.NewConfigBuilder(config, connection)
	writeConfigs := configBuilder.Writes()
	if len(writeConfigs) == 0 {
		return nil, errors.New("not found database configuration")
	}

	gorm, err := NewGorm(config, configBuilder)
	if err != nil {
		return nil, err
	}

	return NewQuery(ctx, config, writeConfigs[0], gorm, log, nil), nil
}

func (r *Query) Association(association string) contractsorm.Association {
	query := r.buildConditions()

	return query.instance.Association(association)
}

func (r *Query) Begin() (contractsorm.Query, error) {
	tx := r.instance.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	return r.new(tx), nil
}

func (r *Query) Commit() error {
	return r.instance.Commit().Error
}

func (r *Query) Count(count *int64) error {
	query := r.buildConditions()

	return query.instance.Count(count).Error
}

func (r *Query) Create(value any) error {
	query, err := r.refreshConnection(value)
	if err != nil {
		return err
	}
	query = query.buildConditions()

	if len(query.instance.Statement.Selects) > 0 && len(query.instance.Statement.Omits) > 0 {
		return errors.New("cannot set Select and Omits at the same time")
	}

	if len(query.instance.Statement.Selects) > 0 {
		return query.selectCreate(value)
	}

	if len(query.instance.Statement.Omits) > 0 {
		return query.omitCreate(value)
	}

	return query.create(value)
}

func (r *Query) Cursor() (chan contractsorm.Cursor, error) {
	with := r.conditions.with
	query := r.buildConditions()
	r.conditions.with = with

	var err error
	cursorChan := make(chan contractsorm.Cursor)
	go func() {
		var rows *sql.Rows
		rows, err = query.instance.Rows()
		if err != nil {
			return
		}
		defer rows.Close()

		for rows.Next() {
			val := make(map[string]any)
			err = query.instance.ScanRows(rows, val)
			if err != nil {
				return
			}
			cursorChan <- &CursorImpl{query: r, row: val}
		}
		close(cursorChan)
	}()
	return cursorChan, err
}

func (r *Query) Delete(dest ...any) (*contractsorm.Result, error) {
	var (
		realDest any
		err      error
	)

	query := r.buildConditions()

	if len(dest) > 0 {
		realDest = dest[0]
		query, err = query.refreshConnection(realDest)
		if err != nil {
			return nil, err
		}
	}

	if err := query.deleting(realDest); err != nil {
		return nil, err
	}

	res := query.instance.Delete(realDest)
	if res.Error != nil {
		return nil, res.Error
	}

	if err := query.deleted(realDest); err != nil {
		return nil, err
	}

	return &contractsorm.Result{
		RowsAffected: res.RowsAffected,
	}, nil
}

func (r *Query) Distinct(args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.distinct = append(conditions.distinct, args...)

	return r.setConditions(conditions)
}

func (r *Query) Driver() contractsdatabase.Driver {
	return contractsdatabase.Driver(r.instance.Dialector.Name())
}

func (r *Query) Exec(sql string, values ...any) (*contractsorm.Result, error) {
	query := r.buildConditions()
	result := query.instance.Exec(sql, values...)

	return &contractsorm.Result{
		RowsAffected: result.RowsAffected,
	}, result.Error
}

func (r *Query) Exists(exists *bool) error {
	query := r.buildConditions()

	return query.instance.Select("1").Limit(1).Find(exists).Error
}

func (r *Query) Find(dest any, conds ...any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if err := filterFindConditions(conds...); err != nil {
		return err
	}
	if err := query.instance.Find(dest, conds...).Error; err != nil {
		return err
	}

	return query.retrieved(dest)
}

func (r *Query) FindOrFail(dest any, conds ...any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if err := filterFindConditions(conds...); err != nil {
		return err
	}

	res := query.instance.Find(dest, conds...)
	if err := res.Error; err != nil {
		return err
	}

	if res.RowsAffected == 0 {
		return orm.ErrRecordNotFound
	}

	return query.retrieved(dest)
}

func (r *Query) First(dest any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	res := query.instance.First(dest)
	if res.Error != nil {
		if errors.Is(res.Error, gormio.ErrRecordNotFound) {
			return nil
		}

		return res.Error
	}

	return query.retrieved(dest)
}

func (r *Query) FirstOr(dest any, callback func() error) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if err := query.instance.First(dest).Error; err != nil {
		if errors.Is(err, gormio.ErrRecordNotFound) {
			return callback()
		}

		return err
	}

	return query.retrieved(dest)
}

func (r *Query) FirstOrCreate(dest any, conds ...any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if len(conds) == 0 {
		return errors.New("query condition is require")
	}

	var res *gormio.DB
	if len(conds) > 1 {
		res = query.instance.Attrs(conds[1]).FirstOrInit(dest, conds[0])
	} else {
		res = query.instance.FirstOrInit(dest, conds[0])
	}

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return query.retrieved(dest)
	}

	return query.Create(dest)
}

func (r *Query) FirstOrFail(dest any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if err := query.instance.First(dest).Error; err != nil {
		if errors.Is(err, gormio.ErrRecordNotFound) {
			return orm.ErrRecordNotFound
		}

		return err
	}

	return query.retrieved(dest)
}

func (r *Query) FirstOrNew(dest any, attributes any, values ...any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	var res *gormio.DB
	if len(values) > 0 {
		res = query.instance.Attrs(values[0]).FirstOrInit(dest, attributes)
	} else {
		res = query.instance.FirstOrInit(dest, attributes)
	}

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return query.retrieved(dest)
	}

	return nil
}

func (r *Query) ForceDelete(dest ...any) (*contractsorm.Result, error) {
	var (
		realDest any
		err      error
	)

	query := r.buildConditions()

	if len(dest) > 0 {
		realDest = dest[0]
		query, err = query.refreshConnection(realDest)
		if err != nil {
			return nil, err
		}
	}

	if err := query.forceDeleting(realDest); err != nil {
		return nil, err
	}

	res := query.instance.Unscoped().Delete(realDest)
	if res.Error != nil {
		return nil, res.Error
	}

	if res.RowsAffected > 0 {
		if err := query.forceDeleted(realDest); err != nil {
			return nil, err
		}
	}

	return &contractsorm.Result{
		RowsAffected: res.RowsAffected,
	}, res.Error
}

func (r *Query) Get(dest any) error {
	return r.Find(dest)
}

func (r *Query) Group(name string) contractsorm.Query {
	conditions := r.conditions
	conditions.group = name

	return r.setConditions(conditions)
}

func (r *Query) Having(query any, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.having = &Having{
		query: query,
		args:  args,
	}

	return r.setConditions(conditions)
}

func (r *Query) Instance() *gormio.DB {
	return r.instance
}

func (r *Query) Join(query string, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.join = append(conditions.join, Join{
		query: query,
		args:  args,
	})

	return r.setConditions(conditions)
}

func (r *Query) Limit(limit int) contractsorm.Query {
	conditions := r.conditions
	conditions.limit = &limit

	return r.setConditions(conditions)
}

func (r *Query) Load(model any, relation string, args ...any) error {
	if relation == "" {
		return errors.New("relation cannot be empty")
	}

	destType := reflect.TypeOf(model)
	if destType.Kind() != reflect.Pointer {
		return errors.New("model must be pointer")
	}

	if id := database.GetID(model); id == nil {
		return errors.New("id cannot be empty")
	}

	copyDest := copyStruct(model)
	err := r.With(relation, args...).Find(model)

	t := destType.Elem()
	v := reflect.ValueOf(model).Elem()
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		if t.Field(i).Name != relation {
			v.Field(i).Set(copyDest.Field(i))
		}
	}

	return err
}

func (r *Query) LoadMissing(model any, relation string, args ...any) error {
	destType := reflect.TypeOf(model)
	if destType.Kind() != reflect.Pointer {
		return errors.New("model must be pointer")
	}

	t := reflect.TypeOf(model).Elem()
	v := reflect.ValueOf(model).Elem()
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		if t.Field(i).Name == relation {
			var id any
			if v.Field(i).Kind() == reflect.Pointer {
				if !v.Field(i).IsNil() {
					id = database.GetIDByReflect(v.Field(i).Type().Elem(), v.Field(i).Elem())
				}
			} else if v.Field(i).Kind() == reflect.Slice {
				if v.Field(i).Len() > 0 {
					return nil
				}
			} else {
				id = database.GetIDByReflect(v.Field(i).Type(), v.Field(i))
			}
			if cast.ToString(id) != "" {
				return nil
			}
		}
	}

	return r.Load(model, relation, args...)
}

func (r *Query) LockForUpdate() contractsorm.Query {
	conditions := r.conditions
	conditions.lockForUpdate = true

	return r.setConditions(conditions)
}

func (r *Query) Model(value any) contractsorm.Query {
	conditions := r.conditions
	conditions.model = value

	return r.setConditions(conditions)
}

func (r *Query) Offset(offset int) contractsorm.Query {
	conditions := r.conditions
	conditions.offset = &offset

	return r.setConditions(conditions)
}

func (r *Query) Omit(columns ...string) contractsorm.Query {
	conditions := r.conditions
	conditions.omit = columns

	return r.setConditions(conditions)
}

func (r *Query) Order(value any) contractsorm.Query {
	conditions := r.conditions
	conditions.order = append(r.conditions.order, value)

	return r.setConditions(conditions)
}

func (r *Query) OrderBy(column string, direction ...string) contractsorm.Query {
	var orderDirection string
	if len(direction) > 0 {
		orderDirection = direction[0]
	} else {
		orderDirection = "ASC"
	}
	return r.Order(fmt.Sprintf("%s %s", column, orderDirection))
}

func (r *Query) OrderByDesc(column string) contractsorm.Query {
	return r.Order(fmt.Sprintf("%s DESC", column))
}

func (r *Query) InRandomOrder() contractsorm.Query {
	order := ""
	switch r.Driver() {
	case contractsdatabase.DriverMysql:
		order = "RAND()"
	case contractsdatabase.DriverSqlserver:
		order = "NEWID()"
	case contractsdatabase.DriverPostgres:
		order = "RANDOM()"
	case contractsdatabase.DriverSqlite:
		order = "RANDOM()"
	}
	return r.Order(order)
}

func (r *Query) OrWhere(query any, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.where = append(r.conditions.where, Where{
		query: query,
		args:  args,
		or:    true,
	})

	return r.setConditions(conditions)
}

func (r *Query) Paginate(page, limit int, dest any, total *int64) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	offset := (page - 1) * limit
	if total != nil {
		if query.conditions.table == nil && query.conditions.model == nil {
			if err := query.Model(dest).Count(total); err != nil {
				return err
			}
		} else {
			if err := query.Count(total); err != nil {
				return err
			}
		}
	}

	return query.Offset(offset).Limit(limit).Find(dest)
}

func (r *Query) Pluck(column string, dest any) error {
	query := r.buildConditions()

	return query.instance.Pluck(column, dest).Error
}

func (r *Query) Raw(sql string, values ...any) contractsorm.Query {
	return r.new(r.instance.Raw(sql, values...))
}

func (r *Query) Rollback() error {
	return r.instance.Rollback().Error
}

func (r *Query) Save(value any) error {
	query, err := r.refreshConnection(value)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	if len(query.instance.Statement.Selects) > 0 && len(query.instance.Statement.Omits) > 0 {
		return errors.New("cannot set Select and Omits at the same time")
	}

	id := database.GetID(value)
	update := id != nil

	if err := query.saving(value); err != nil {
		return err
	}
	if update {
		if err := query.updating(value); err != nil {
			return err
		}
	} else {
		if err := query.creating(value); err != nil {
			return err
		}
	}

	if len(query.instance.Statement.Selects) > 0 {
		if err := query.selectSave(value); err != nil {
			return err
		}
	} else if len(query.instance.Statement.Omits) > 0 {
		if err := query.omitSave(value); err != nil {
			return err
		}
	} else {
		if err := query.save(value); err != nil {
			return err
		}
	}

	if update {
		if err := query.updated(value); err != nil {
			return err
		}
	} else {
		if err := query.created(value); err != nil {
			return err
		}
	}
	if err := query.saved(value); err != nil {
		return err
	}

	return nil
}

func (r *Query) SaveQuietly(value any) error {
	return r.WithoutEvents().Save(value)
}

func (r *Query) Scan(dest any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	return query.instance.Scan(dest).Error
}

func (r *Query) Scopes(funcs ...func(contractsorm.Query) contractsorm.Query) contractsorm.Query {
	conditions := r.conditions
	conditions.scopes = append(r.conditions.scopes, funcs...)

	return r.setConditions(conditions)
}

func (r *Query) Select(query any, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.selectColumns = &Select{
		query: query,
		args:  args,
	}

	return r.setConditions(conditions)
}

func (r *Query) SetContext(ctx context.Context) {
	r.ctx = ctx
	r.instance.Statement.Context = ctx
}

func (r *Query) SharedLock() contractsorm.Query {
	conditions := r.conditions
	conditions.sharedLock = true

	return r.setConditions(conditions)
}

func (r *Query) Sum(column string, dest any) error {
	query := r.buildConditions()

	return query.instance.Select("SUM(" + column + ")").Row().Scan(dest)
}

func (r *Query) Table(name string, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.table = &Table{
		name: r.fullConfig.Prefix + name,
		args: args,
	}

	return r.setConditions(conditions)
}

func (r *Query) ToSql() contractsorm.ToSql {
	return NewToSql(r.setConditions(r.conditions), r.log, false)
}

func (r *Query) ToRawSql() contractsorm.ToSql {
	return NewToSql(r.setConditions(r.conditions), r.log, true)
}

func (r *Query) Update(column any, value ...any) (*contractsorm.Result, error) {
	query := r.buildConditions()

	if _, ok := column.(string); !ok && len(value) > 0 {
		return nil, errors.New("parameter error, please check the document")
	}

	var singleUpdate bool
	model := query.instance.Statement.Model
	if model != nil {
		id := database.GetID(model)
		singleUpdate = id != nil
	}

	if c, ok := column.(string); ok && len(value) > 0 {
		query.instance.Statement.Dest = map[string]any{c: value[0]}
	}
	if len(value) == 0 {
		query.instance.Statement.Dest = column
	}

	if singleUpdate {
		if err := query.saving(query.instance.Statement.Dest); err != nil {
			return nil, err
		}
		if err := query.updating(query.instance.Statement.Dest); err != nil {
			return nil, err
		}
	}

	res, err := query.updates(query.instance.Statement.Dest)

	if singleUpdate && err == nil {
		if err := query.updated(query.instance.Statement.Dest); err != nil {
			return nil, err
		}
		if err := query.saved(query.instance.Statement.Dest); err != nil {
			return nil, err
		}
	}

	return res, err
}

func (r *Query) UpdateOrCreate(dest any, attributes any, values any) error {
	query, err := r.refreshConnection(dest)
	if err != nil {
		return err
	}

	query = query.buildConditions()

	res := query.instance.Assign(values).FirstOrInit(dest, attributes)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return query.Save(dest)
	}

	return query.Create(dest)
}

func (r *Query) Where(query any, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.where = append(r.conditions.where, Where{
		query: query,
		args:  args,
	})

	return r.setConditions(conditions)
}

func (r *Query) WhereIn(column string, values []any) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s IN ?", column), values)
}

func (r *Query) OrWhereIn(column string, values []any) contractsorm.Query {
	return r.OrWhere(fmt.Sprintf("%s IN ?", column), values)
}

func (r *Query) WhereNotIn(column string, values []any) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s NOT IN ?", column), values)
}

func (r *Query) OrWhereNotIn(column string, values []any) contractsorm.Query {
	return r.OrWhere(fmt.Sprintf("%s NOT IN ?", column), values)
}

func (r *Query) WhereBetween(column string, x, y any) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s BETWEEN %v AND %v", column, x, y))
}

func (r *Query) WhereNotBetween(column string, x, y any) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s NOT BETWEEN %v AND %v", column, x, y))
}

func (r *Query) OrWhereBetween(column string, x, y any) contractsorm.Query {
	return r.OrWhere(fmt.Sprintf("%s BETWEEN %v AND %v", column, x, y))
}

func (r *Query) OrWhereNotBetween(column string, x, y any) contractsorm.Query {
	return r.OrWhere(fmt.Sprintf("%s NOT BETWEEN %v AND %v", column, x, y))
}

func (r *Query) OrWhereNull(column string) contractsorm.Query {
	return r.OrWhere(fmt.Sprintf("%s IS NULL", column))
}

func (r *Query) WhereNull(column string) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s IS NULL", column))
}

func (r *Query) WhereNotNull(column string) contractsorm.Query {
	return r.Where(fmt.Sprintf("%s IS NOT NULL", column))
}

func (r *Query) With(query string, args ...any) contractsorm.Query {
	conditions := r.conditions
	conditions.with = append(r.conditions.with, With{
		query: query,
		args:  args,
	})

	return r.setConditions(conditions)
}

func (r *Query) WithoutEvents() contractsorm.Query {
	conditions := r.conditions
	conditions.withoutEvents = true

	return r.setConditions(conditions)
}

func (r *Query) WithTrashed() contractsorm.Query {
	conditions := r.conditions
	conditions.withTrashed = true

	return r.setConditions(conditions)
}

func (r *Query) buildConditions() *Query {
	query := r.buildModel()
	db := query.instance
	db = query.buildDistinct(db)
	db = query.buildGroup(db)
	db = query.buildHaving(db)
	db = query.buildJoin(db)
	db = query.buildLockForUpdate(db)
	db = query.buildLimit(db)
	db = query.buildOrder(db)
	db = query.buildOffset(db)
	db = query.buildOmit(db)
	db = query.buildScopes(db)
	db = query.buildSelectColumns(db)
	db = query.buildSharedLock(db)
	db = query.buildTable(db)
	db = query.buildWith(db)
	db = query.buildWithTrashed(db)
	db = query.buildWhere(db)

	return query.new(db)
}

func (r *Query) buildDistinct(db *gormio.DB) *gormio.DB {
	if len(r.conditions.distinct) == 0 {
		return db
	}

	db = db.Distinct(r.conditions.distinct...)
	r.conditions.distinct = nil

	return db
}

func (r *Query) buildGroup(db *gormio.DB) *gormio.DB {
	if r.conditions.group == "" {
		return db
	}

	db = db.Group(r.conditions.group)
	r.conditions.group = ""

	return db
}

func (r *Query) buildHaving(db *gormio.DB) *gormio.DB {
	if r.conditions.having == nil {
		return db
	}

	db = db.Having(r.conditions.having.query, r.conditions.having.args...)
	r.conditions.having = nil

	return db
}

func (r *Query) buildJoin(db *gormio.DB) *gormio.DB {
	if r.conditions.join == nil {
		return db
	}

	for _, item := range r.conditions.join {
		db = db.Joins(item.query, item.args...)
	}

	r.conditions.join = nil

	return db
}

func (r *Query) buildLimit(db *gormio.DB) *gormio.DB {
	if r.conditions.limit == nil {
		return db
	}

	db = db.Limit(*r.conditions.limit)
	r.conditions.limit = nil

	return db
}

func (r *Query) buildLockForUpdate(db *gormio.DB) *gormio.DB {
	if !r.conditions.lockForUpdate {
		return db
	}

	driver := r.instance.Name()
	mysqlDialector := mysql.Dialector{}
	postgresDialector := postgres.Dialector{}
	sqlserverDialector := sqlserver.Dialector{}

	if driver == mysqlDialector.Name() || driver == postgresDialector.Name() {
		return db.Clauses(clause.Locking{Strength: "UPDATE"})
	} else if driver == sqlserverDialector.Name() {
		return db.Clauses(hints.With("rowlock", "updlock", "holdlock"))
	}

	r.conditions.lockForUpdate = false

	return db
}

func (r *Query) buildModel() *Query {
	if r.conditions.model == nil {
		return r
	}

	query, err := r.refreshConnection(r.conditions.model)
	if err != nil {
		query = r.new(r.instance.Session(&gormio.Session{}))
		_ = query.instance.AddError(err)

		return query
	}

	return query.new(query.instance.Model(r.conditions.model))
}

func (r *Query) buildOffset(db *gormio.DB) *gormio.DB {
	if r.conditions.offset == nil {
		return db
	}

	db = db.Offset(*r.conditions.offset)
	r.conditions.offset = nil

	return db
}

func (r *Query) buildOmit(db *gormio.DB) *gormio.DB {
	if len(r.conditions.omit) == 0 {
		return db
	}

	db = db.Omit(r.conditions.omit...)
	r.conditions.omit = nil

	return db
}

func (r *Query) buildOrder(db *gormio.DB) *gormio.DB {
	if len(r.conditions.order) == 0 {
		return db
	}

	for _, order := range r.conditions.order {
		db = db.Order(order)
	}

	r.conditions.order = nil

	return db
}

func (r *Query) buildSelectColumns(db *gormio.DB) *gormio.DB {
	if r.conditions.selectColumns == nil {
		return db
	}

	db = db.Select(r.conditions.selectColumns.query, r.conditions.selectColumns.args...)
	r.conditions.selectColumns = nil

	return db
}

func (r *Query) buildScopes(db *gormio.DB) *gormio.DB {
	if len(r.conditions.scopes) == 0 {
		return db
	}

	var gormFuncs []func(*gormio.DB) *gormio.DB
	for _, scope := range r.conditions.scopes {
		currentScope := scope
		gormFuncs = append(gormFuncs, func(tx *gormio.DB) *gormio.DB {
			queryImpl := r.new(tx)
			query := currentScope(queryImpl)
			queryImpl = query.(*Query)
			queryImpl = queryImpl.buildConditions()

			return queryImpl.instance
		})
	}

	db = db.Scopes(gormFuncs...)
	r.conditions.scopes = nil

	return db
}

func (r *Query) buildSharedLock(db *gormio.DB) *gormio.DB {
	if !r.conditions.sharedLock {
		return db
	}

	driver := r.instance.Name()
	mysqlDialector := mysql.Dialector{}
	postgresDialector := postgres.Dialector{}
	sqlserverDialector := sqlserver.Dialector{}

	if driver == mysqlDialector.Name() || driver == postgresDialector.Name() {
		return db.Clauses(clause.Locking{Strength: "SHARE"})
	} else if driver == sqlserverDialector.Name() {
		return db.Clauses(hints.With("rowlock", "holdlock"))
	}

	r.conditions.sharedLock = false

	return db
}

func (r *Query) buildTable(db *gormio.DB) *gormio.DB {
	if r.conditions.table == nil {
		return db
	}

	db = db.Table(r.conditions.table.name, r.conditions.table.args...)
	r.conditions.table = nil

	return db
}

func (r *Query) buildWhere(db *gormio.DB) *gormio.DB {
	if len(r.conditions.where) == 0 {
		return db
	}

	for _, item := range r.conditions.where {
		if item.or {
			db = db.Or(item.query, item.args...)
		} else {
			db = db.Where(item.query, item.args...)
		}
	}

	r.conditions.where = nil

	return db
}

func (r *Query) buildWith(db *gormio.DB) *gormio.DB {
	if len(r.conditions.with) == 0 {
		return db
	}

	for _, item := range r.conditions.with {
		isSet := false
		if len(item.args) == 1 {
			if arg, ok := item.args[0].(func(contractsorm.Query) contractsorm.Query); ok {
				newArgs := []any{
					func(tx *gormio.DB) *gormio.DB {
						queryImpl := NewQuery(r.ctx, r.config, r.fullConfig, tx, r.log, nil)
						query := arg(queryImpl)
						queryImpl = query.(*Query)
						queryImpl = queryImpl.buildConditions()

						return queryImpl.instance
					},
				}

				db = db.Preload(item.query, newArgs...)
				isSet = true
			}
		}

		if !isSet {
			db = db.Preload(item.query, item.args...)
		}
	}

	r.conditions.with = nil

	return db
}

func (r *Query) buildWithTrashed(db *gormio.DB) *gormio.DB {
	if !r.conditions.withTrashed {
		return db
	}

	db = db.Unscoped()
	r.conditions.withTrashed = false

	return db
}

func (r *Query) clearConditions() {
	r.conditions = Conditions{}
}

func (r *Query) create(dest any) error {
	if err := r.saving(dest); err != nil {
		return err
	}
	if err := r.creating(dest); err != nil {
		return err
	}

	if err := r.instance.Omit(orm.Associations).Create(dest).Error; err != nil {
		return err
	}

	if err := r.created(dest); err != nil {
		return err
	}
	if err := r.saved(dest); err != nil {
		return err
	}

	return nil
}

func (r *Query) created(dest any) error {
	return r.event(contractsorm.EventCreated, r.instance.Statement.Model, dest)
}

func (r *Query) creating(dest any) error {
	return r.event(contractsorm.EventCreating, r.instance.Statement.Model, dest)
}

func (r *Query) deleting(dest any) error {
	return r.event(contractsorm.EventDeleting, r.instance.Statement.Model, dest)
}

func (r *Query) deleted(dest any) error {
	return r.event(contractsorm.EventDeleted, r.instance.Statement.Model, dest)
}

func (r *Query) forceDeleting(dest any) error {
	return r.event(contractsorm.EventForceDeleting, r.instance.Statement.Model, dest)
}

func (r *Query) forceDeleted(dest any) error {
	return r.event(contractsorm.EventForceDeleted, r.instance.Statement.Model, dest)
}

func (r *Query) event(event contractsorm.EventType, model, dest any) error {
	if r.conditions.withoutEvents {
		return nil
	}

	instance := NewEvent(r, model, dest)

	if dest != nil {
		if dispatchesEvents, exist := dest.(contractsorm.DispatchesEvents); exist {
			if dispatchesEvent, exists := dispatchesEvents.DispatchesEvents()[event]; exists {
				return dispatchesEvent(instance)
			}
			return nil
		}
	}

	if model != nil {
		if dispatchesEvents, exist := model.(contractsorm.DispatchesEvents); exist {
			if dispatchesEvent, exists := dispatchesEvents.DispatchesEvents()[event]; exists {
				return dispatchesEvent(instance)
			}

			return nil
		}
	}

	if dest != nil {
		if observer := getObserver(dest); observer != nil {
			if observerEvent := getObserverEvent(event, observer); observerEvent != nil {
				return observerEvent(instance)
			}
			return nil
		}
	}

	if model != nil {
		if observer := getObserver(model); observer != nil {
			if observerEvent := getObserverEvent(event, observer); observerEvent != nil {
				return observerEvent(instance)
			}

			return nil
		}
	}

	return nil
}

func (r *Query) new(db *gormio.DB) *Query {
	return NewQuery(r.ctx, r.config, r.fullConfig, db, r.log, &r.conditions)
}

func (r *Query) omitCreate(value any) error {
	if len(r.instance.Statement.Omits) > 1 {
		for _, val := range r.instance.Statement.Omits {
			if val == orm.Associations {
				return errors.New("cannot set orm.Associations and other fields at the same time")
			}
		}
	}

	if len(r.instance.Statement.Omits) == 1 && r.instance.Statement.Omits[0] == orm.Associations {
		r.instance.Statement.Selects = []string{}
	}

	if err := r.saving(value); err != nil {
		return err
	}
	if err := r.creating(value); err != nil {
		return err
	}

	if len(r.instance.Statement.Omits) == 1 && r.instance.Statement.Omits[0] == orm.Associations {
		if err := r.instance.Omit(orm.Associations).Create(value).Error; err != nil {
			return err
		}
	} else {
		if err := r.instance.Create(value).Error; err != nil {
			return err
		}
	}

	if err := r.created(value); err != nil {
		return err
	}
	if err := r.saved(value); err != nil {
		return err
	}

	return nil
}

func (r *Query) omitSave(value any) error {
	for _, val := range r.instance.Statement.Omits {
		if val == orm.Associations {
			return r.instance.Omit(orm.Associations).Save(value).Error
		}
	}

	return r.instance.Save(value).Error
}

func (r *Query) refreshConnection(model any) (*Query, error) {
	connection, err := getModelConnection(model)
	if err != nil {
		return nil, err
	}
	if connection == "" || connection == r.fullConfig.Connection {
		return r, nil
	}

	query, ok := r.queries[connection]
	if !ok {
		var err error
		query, err = BuildQuery(r.ctx, r.config, connection, r.log)
		if err != nil {
			return nil, err
		}

		if r.queries == nil {
			r.queries = make(map[string]*Query)
		}
		r.queries[connection] = query
	}

	query.conditions = r.conditions

	return query, nil
}

func (r *Query) retrieved(dest any) error {
	return r.event(contractsorm.EventRetrieved, nil, dest)
}

func (r *Query) save(value any) error {
	return r.instance.Omit(orm.Associations).Save(value).Error
}

func (r *Query) saved(dest any) error {
	return r.event(contractsorm.EventSaved, r.instance.Statement.Model, dest)
}

func (r *Query) saving(dest any) error {
	return r.event(contractsorm.EventSaving, r.instance.Statement.Model, dest)
}

func (r *Query) selectCreate(value any) error {
	if len(r.instance.Statement.Selects) > 1 {
		for _, val := range r.instance.Statement.Selects {
			if val == orm.Associations {
				return errors.New("cannot set orm.Associations and other fields at the same time")
			}
		}
	}

	if len(r.instance.Statement.Selects) == 1 && r.instance.Statement.Selects[0] == orm.Associations {
		r.instance.Statement.Selects = []string{}
	}

	if err := r.saving(value); err != nil {
		return err
	}
	if err := r.creating(value); err != nil {
		return err
	}

	if err := r.instance.Create(value).Error; err != nil {
		return err
	}

	if err := r.created(value); err != nil {
		return err
	}
	if err := r.saved(value); err != nil {
		return err
	}

	return nil
}

func (r *Query) selectSave(value any) error {
	for _, val := range r.instance.Statement.Selects {
		if val == orm.Associations {
			return r.instance.Session(&gormio.Session{FullSaveAssociations: true}).Save(value).Error
		}
	}

	if err := r.instance.Save(value).Error; err != nil {
		return err
	}

	return nil
}

func (r *Query) setConditions(conditions Conditions) *Query {
	query := r.new(r.instance)
	query.conditions = conditions

	return query
}

func (r *Query) updating(dest any) error {
	return r.event(contractsorm.EventUpdating, r.instance.Statement.Model, dest)
}

func (r *Query) updated(dest any) error {
	return r.event(contractsorm.EventUpdated, r.instance.Statement.Model, dest)
}

func (r *Query) updates(values any) (*contractsorm.Result, error) {
	if len(r.instance.Statement.Selects) > 0 && len(r.instance.Statement.Omits) > 0 {
		return nil, errors.New("cannot set Select and Omits at the same time")
	}

	if len(r.instance.Statement.Selects) > 0 {
		for _, val := range r.instance.Statement.Selects {
			if val == orm.Associations {
				result := r.instance.Session(&gormio.Session{FullSaveAssociations: true}).Updates(values)
				return &contractsorm.Result{
					RowsAffected: result.RowsAffected,
				}, result.Error
			}
		}

		result := r.instance.Updates(values)

		return &contractsorm.Result{
			RowsAffected: result.RowsAffected,
		}, result.Error
	}

	if len(r.instance.Statement.Omits) > 0 {
		for _, val := range r.instance.Statement.Omits {
			if val == orm.Associations {
				result := r.instance.Omit(orm.Associations).Updates(values)

				return &contractsorm.Result{
					RowsAffected: result.RowsAffected,
				}, result.Error
			}
		}
		result := r.instance.Updates(values)

		return &contractsorm.Result{
			RowsAffected: result.RowsAffected,
		}, result.Error
	}
	result := r.instance.Omit(orm.Associations).Updates(values)

	return &contractsorm.Result{
		RowsAffected: result.RowsAffected,
	}, result.Error
}

func filterFindConditions(conds ...any) error {
	if len(conds) > 0 {
		switch cond := conds[0].(type) {
		case string:
			if cond == "" {
				return ErrorMissingWhereClause
			}
		default:
			reflectValue := reflect.Indirect(reflect.ValueOf(cond))
			switch reflectValue.Kind() {
			case reflect.Slice, reflect.Array:
				if reflectValue.Len() == 0 {
					return ErrorMissingWhereClause
				}
			}
		}
	}

	return nil
}

func getModelConnection(model any) (string, error) {
	modelValue := reflect.ValueOf(model)
	if modelValue.Kind() == reflect.Ptr && modelValue.IsNil() {
		// If the model is a pointer and is nil, we will create a new instance of the model
		modelValue = reflect.New(modelValue.Type().Elem())
	}
	modelType := reflect.Indirect(modelValue).Type()

	if modelType.Kind() == reflect.Interface {
		modelType = reflect.Indirect(modelValue).Elem().Type()
	}

	for modelType.Kind() == reflect.Slice || modelType.Kind() == reflect.Array || modelType.Kind() == reflect.Ptr {
		modelType = modelType.Elem()
	}

	if modelType.Kind() == reflect.Map {
		return "", nil
	}

	if modelType.Kind() != reflect.Struct {
		if modelType.PkgPath() == "" {
			return "", errors.New("invalid model")
		}
		return "", fmt.Errorf("%s: %s.%s", "invalid model", modelType.PkgPath(), modelType.Name())
	}

	newModel := reflect.New(modelType)
	connectionModel, ok := newModel.Interface().(contractsorm.ConnectionModel)
	if !ok {
		return "", nil
	}

	return connectionModel.Connection(), nil
}

func getObserver(dest any) contractsorm.Observer {
	destType := reflect.TypeOf(dest)
	if destType.Kind() == reflect.Pointer {
		destType = destType.Elem()
	}

	for _, observer := range orm.Observers {
		modelType := reflect.TypeOf(observer.Model)
		if modelType.Kind() == reflect.Pointer {
			modelType = modelType.Elem()
		}
		if destType.Name() == modelType.Name() {
			return observer.Observer
		}
	}

	return nil
}

func getObserverEvent(event contractsorm.EventType, observer contractsorm.Observer) func(contractsorm.Event) error {
	switch event {
	case contractsorm.EventRetrieved:
		return observer.Retrieved
	case contractsorm.EventCreating:
		return observer.Creating
	case contractsorm.EventCreated:
		return observer.Created
	case contractsorm.EventUpdating:
		return observer.Updating
	case contractsorm.EventUpdated:
		return observer.Updated
	case contractsorm.EventSaving:
		return observer.Saving
	case contractsorm.EventSaved:
		return observer.Saved
	case contractsorm.EventDeleting:
		return observer.Deleting
	case contractsorm.EventDeleted:
		return observer.Deleted
	case contractsorm.EventForceDeleting:
		return observer.ForceDeleting
	case contractsorm.EventForceDeleted:
		return observer.ForceDeleted
	}

	return nil
}
