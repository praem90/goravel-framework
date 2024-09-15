package auth

import (
	"testing"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/http"
	configmock "github.com/goravel/framework/mocks/config"
	foundationMock "github.com/goravel/framework/mocks/foundation"
	"github.com/stretchr/testify/suite"
)

type AuthManagerTestSuite struct {
	suite.Suite
	app         *foundationMock.Application
	mockContext http.Context
	manager     AuthManager
	config      *configmock.Config
}

func TestAuthManagerSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerTestSuite))
}

func (s *AuthManagerTestSuite) SetupTest() {
	s.mockContext = Background()
	s.app = &foundationMock.Application{}
	s.config = &configmock.Config{}
	s.manager = AuthManager{
		app:    s.app,
		ctx:    s.mockContext,
		guards: make(map[string]contractsauth.AuthGuardFunc),
	}
}

func (s *AuthManagerTestSuite) TestValidExtend() {
	s.manager.Extend("jwt", NewJwtGuard)
	s.config.On("GetString", "auth.guards.test.driver").Once().Return("jwt")
	s.app.On("MakeConfig").Return(s.config)

	jwtGuard := s.manager.Guard("test")

	_, ok := jwtGuard.(contractsauth.Auth)

	s.Assert().True(true, ok)
}

func (s *AuthManagerTestSuite) TestInValidExtend() {
	s.config.On("GetString", "auth.guards.test.driver").Once().Return("invalid")
	s.app.On("MakeConfig").Return(s.config)

	testGuard := s.manager.Guard("test")

	s.Assert().Nil(testGuard)
}

type JwtGuard struct {
}

// Id implements auth.Auth.
func (j JwtGuard) Id() (string, error) {
	panic("unimplemented")
}

// Guard implements auth.Auth.
func (j JwtGuard) Guard(name string) contractsauth.Auth {
	panic("unimplemented")
}

// Login implements auth.Auth.
func (j JwtGuard) Login(user any) (token string, err error) {
	panic("unimplemented")
}

// LoginUsingID implements auth.Auth.
func (j JwtGuard) LoginUsingID(id any) (token string, err error) {
	panic("unimplemented")
}

// Logout implements auth.Auth.
func (j JwtGuard) Logout() error {
	panic("unimplemented")
}

// Parse implements auth.Auth.
func (j JwtGuard) Parse(token string) (*contractsauth.Payload, error) {
	panic("unimplemented")
}

// Refresh implements auth.Auth.
func (j JwtGuard) Refresh() (token string, err error) {
	panic("unimplemented")
}

// User implements auth.Auth.
func (j JwtGuard) User(user any) error {
	panic("unimplemented")
}

func NewJwtGuard(string, config.Config, http.Context) contractsauth.Auth {
	return &JwtGuard{}
}
