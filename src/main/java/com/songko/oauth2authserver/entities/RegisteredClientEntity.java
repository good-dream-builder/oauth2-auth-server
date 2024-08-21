package com.songko.oauth2authserver.entities;

import jakarta.persistence.*;

import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "registered_clients")
public class RegisteredClientEntity {
    @Id
    private String id = UUID.randomUUID().toString();

    private String clientId;

    private String clientSecret;

    @ElementCollection(targetClass = String.class)
    @CollectionTable(name = "client_authentication_methods")
    @Column(name = "authentication_method")
    private Set<String> clientAuthenticationMethods;

    @ElementCollection(targetClass = String.class)
    @CollectionTable(name = "authorization_grant_types")
    @Column(name = "grant_type")
    private Set<String> authorizationGrantTypes;

    private String redirectUri;

    private String postLogoutRedirectUri;

    @ElementCollection(targetClass = String.class)
    @CollectionTable(name = "scopes")
    @Column(name = "scope")
    private Set<String> scopes;

    private boolean requireAuthorizationConsent;
}
