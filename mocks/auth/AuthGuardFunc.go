// Code generated by mockery. DO NOT EDIT.

package auth

import (
	auth "github.com/goravel/framework/contracts/auth"
	config "github.com/goravel/framework/contracts/config"

	http "github.com/goravel/framework/contracts/http"

	mock "github.com/stretchr/testify/mock"
)

// AuthGuardFunc is an autogenerated mock type for the AuthGuardFunc type
type AuthGuardFunc struct {
	mock.Mock
}

type AuthGuardFunc_Expecter struct {
	mock *mock.Mock
}

func (_m *AuthGuardFunc) EXPECT() *AuthGuardFunc_Expecter {
	return &AuthGuardFunc_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: _a0, _a1, _a2
func (_m *AuthGuardFunc) Execute(_a0 string, _a1 config.Config, _a2 http.Context) auth.Auth {
	ret := _m.Called(_a0, _a1, _a2)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 auth.Auth
	if rf, ok := ret.Get(0).(func(string, config.Config, http.Context) auth.Auth); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(auth.Auth)
		}
	}

	return r0
}

// AuthGuardFunc_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type AuthGuardFunc_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - _a0 string
//   - _a1 config.Config
//   - _a2 http.Context
func (_e *AuthGuardFunc_Expecter) Execute(_a0 interface{}, _a1 interface{}, _a2 interface{}) *AuthGuardFunc_Execute_Call {
	return &AuthGuardFunc_Execute_Call{Call: _e.mock.On("Execute", _a0, _a1, _a2)}
}

func (_c *AuthGuardFunc_Execute_Call) Run(run func(_a0 string, _a1 config.Config, _a2 http.Context)) *AuthGuardFunc_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(config.Config), args[2].(http.Context))
	})
	return _c
}

func (_c *AuthGuardFunc_Execute_Call) Return(_a0 auth.Auth) *AuthGuardFunc_Execute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AuthGuardFunc_Execute_Call) RunAndReturn(run func(string, config.Config, http.Context) auth.Auth) *AuthGuardFunc_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewAuthGuardFunc creates a new instance of AuthGuardFunc. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthGuardFunc(t interface {
	mock.TestingT
	Cleanup(func())
}) *AuthGuardFunc {
	mock := &AuthGuardFunc{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
