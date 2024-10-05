package auth

type UserProvider interface {
    RetriveById(any) any;
    RetriveByToken(any) any;
    // This method seems no longer a valid or needed
    UpdateRememberToken(any);
    RetriveByCredentials(map[string]any) any;
    ValidateCredentials(any, map[string]any) bool;
    RehashPasswordIfNeeded(any, map[string]any, bool);
}
