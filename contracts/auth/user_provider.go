package auth

type UserProvider interface {
    RetriveById(any) (any, error);
    RetriveByCredentials(map[string]any) (any, error);
}

