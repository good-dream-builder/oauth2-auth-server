package com.songko.oauth2authserver.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collections;
import java.util.Map;

public class SongkoGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String code;
    private final Map<String, Object> additionalParameters;

    public SongkoGrantAuthenticationToken(String code, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:songko"), clientPrincipal, additionalParameters);
        this.code = code;
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters);
    }

    public String getCode() {
        return code;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }
}
