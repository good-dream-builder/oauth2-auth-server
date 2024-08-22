package com.songko.oauth2authserver.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;
import java.util.function.Consumer;

public final class Oauth2PasswordCredentialsAuthenticationValidator
        implements Consumer<Oauth2PasswordCredentialsAuthenticationContext> {
    private static final Log LOGGER = LogFactory.getLog(Oauth2PasswordCredentialsAuthenticationValidator.class);

    /**
     * The default validator for
     * {@link Oauth2PasswordCredentialsAuthenticationToken#getScopes()}.
     */
    public static final Consumer<Oauth2PasswordCredentialsAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = Oauth2PasswordCredentialsAuthenticationValidator::validateScope;

    private final Consumer<Oauth2PasswordCredentialsAuthenticationContext> authenticationValidator = DEFAULT_SCOPE_VALIDATOR;

    @Override
    public void accept(Oauth2PasswordCredentialsAuthenticationContext authenticationContext) {
        this.authenticationValidator.accept(authenticationContext);
    }

    private static void validateScope(Oauth2PasswordCredentialsAuthenticationContext authenticationContext) {
        Oauth2PasswordCredentialsAuthenticationToken passwordCredentialsAuthentication = authenticationContext
                .getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

        Set<String> requestedScopes = passwordCredentialsAuthentication.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(LogMessage.format(
                        "Invalid request: requested scope is not allowed" + " for registered client '%s'",
                        registeredClient.getId()));
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }
}
