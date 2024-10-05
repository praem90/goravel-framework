package auth

import (
	"testing"

	contractsauth "github.com/goravel/framework/contracts/auth"
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
		guards: map[string]contractsauth.Guard{},
		customGuards: map[string]contractsauth.AuthGuardFunc{},
	}
}

func (s *AuthManagerTestSuite) TestValidExtend() {
	s.manager.Extend("jwt", NewJwtGuard)
	s.config.On("GetString", "auth.guards.test.driver").Once().Return("jwt")
	s.app.On("MakeConfig").Return(s.config)

	jwtGuard := s.manager.Guard("test")

    s.Assert().NotNil(jwtGuard)
}

func (s *AuthManagerTestSuite) TestInValidExtend() {
	s.config.On("GetString", "auth.guards.test.driver").Once().Return("invalid")
	s.app.On("MakeConfig").Return(s.config)

	testGuard := s.manager.Guard("test")

	s.Assert().Nil(testGuard)
}
