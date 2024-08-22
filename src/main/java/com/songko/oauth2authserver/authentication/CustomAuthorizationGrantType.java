package com.songko.oauth2authserver.authentication;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.io.Serializable;

public final class CustomAuthorizationGrantType implements Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    public static final AuthorizationGrantType SONGKO = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:songko");
}
