package com.songko.oauth2authserver.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link Oauth2PasswordCredentialsAuthenticationToken} and additional information and is
 * used when validating the OAuth 2.0 Client Credentials Grant Request.
 *
 * @author Adam Pilling
 * @since 1.3
 * @see OAuth2AuthenticationContext
 * @see Oauth2PasswordCredentialsAuthenticationToken
 * @see Oauth2PasswordCredentialsAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class Oauth2PasswordCredentialsAuthenticationContext implements OAuth2AuthenticationContext {

    private final Map<Object, Object> context;

    public Oauth2PasswordCredentialsAuthenticationContext(Map<Object, Object> context) {
        this.context = Collections.unmodifiableMap(new HashMap<>(context));
    }

    @SuppressWarnings("unchecked")
    @Nullable
    @Override
    public <V> V get(Object key) {
        return hasKey(key) ? (V) this.context.get(key) : null;
    }

    @Override
    public boolean hasKey(Object key) {
        Assert.notNull(key, "key cannot be null");
        return this.context.containsKey(key);
    }

    /**
     * Returns the {@link RegisteredClient registered client}.
     * @return the {@link RegisteredClient}
     */
    public RegisteredClient getRegisteredClient() {
        return get(RegisteredClient.class);
    }

    /**
     * Constructs a new {@link Oauth2PasswordCredentialsAuthenticationContext.Builder} with the provided
     * {@link Oauth2PasswordCredentialsAuthenticationToken}.
     * @param authentication the {@link Oauth2PasswordCredentialsAuthenticationToken}
     * @return the {@link Oauth2PasswordCredentialsAuthenticationContext.Builder}
     */
    public static Oauth2PasswordCredentialsAuthenticationContext.Builder with(Oauth2PasswordCredentialsAuthenticationToken authentication) {
        return new Oauth2PasswordCredentialsAuthenticationContext.Builder(authentication);
    }

    /**
     * A builder for {@link Oauth2PasswordCredentialsAuthenticationContext}.
     */
    public static final class Builder extends AbstractBuilder<Oauth2PasswordCredentialsAuthenticationContext, Builder> {

        private Builder(Oauth2PasswordCredentialsAuthenticationToken authentication) {
            super(authentication);
        }

        /**
         * Sets the {@link RegisteredClient registered client}.
         * @param registeredClient the {@link RegisteredClient}
         * @return the {@link Oauth2PasswordCredentialsAuthenticationContext.Builder} for further configuration
         */
        public Oauth2PasswordCredentialsAuthenticationContext.Builder registeredClient(RegisteredClient registeredClient) {
            return put(RegisteredClient.class, registeredClient);
        }

        /**
         * Builds a new {@link Oauth2PasswordCredentialsAuthenticationContext}.
         * @return the {@link Oauth2PasswordCredentialsAuthenticationContext}
         */
        public Oauth2PasswordCredentialsAuthenticationContext build() {
            Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
            return new Oauth2PasswordCredentialsAuthenticationContext(getContext());
        }

    }
}
