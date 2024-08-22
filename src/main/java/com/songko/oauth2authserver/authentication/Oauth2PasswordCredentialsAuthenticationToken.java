package com.songko.oauth2authserver.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.*;

public class Oauth2PasswordCredentialsAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final Authentication principal;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;
    private String username;
    private String password;

    public Oauth2PasswordCredentialsAuthenticationToken(Authentication principal,
                                                        @Nullable Set<String> scopes,
                                                        @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, principal, additionalParameters);
        this.principal = principal;
        this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap((additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
