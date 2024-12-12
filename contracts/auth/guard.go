package auth

type Guard interface {
    Check() bool;
    Guest() bool;
    // TODO: Authendicatable interface has to be implemented
    User() *any;
    Id() string;
    Validate(map[string]string) bool;
    HasUser() bool;
    SetUser(any) Guard;
}
