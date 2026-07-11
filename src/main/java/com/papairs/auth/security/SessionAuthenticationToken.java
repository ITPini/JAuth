package com.papairs.auth.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import java.util.Collections;

public class SessionAuthenticationToken extends AbstractAuthenticationToken {
    private final SessionPrincipal principal;

    public SessionAuthenticationToken(SessionPrincipal principal) {
        // TODO: Implement proper GrantedAuthority
        super(Collections.emptyList());
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override public Object getPrincipal() {
        return principal;
    }

    @Override public Object getCredentials() {
        return null;
    }
}
