// Code generated by mockery. DO NOT EDIT.

package migration

import mock "github.com/stretchr/testify/mock"

// Migrator is an autogenerated mock type for the Migrator type
type Migrator struct {
	mock.Mock
}

type Migrator_Expecter struct {
	mock *mock.Mock
}

func (_m *Migrator) EXPECT() *Migrator_Expecter {
	return &Migrator_Expecter{mock: &_m.Mock}
}

// NewMigrator creates a new instance of Migrator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMigrator(t interface {
	mock.TestingT
	Cleanup(func())
}) *Migrator {
	mock := &Migrator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
