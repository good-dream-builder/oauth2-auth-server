package com.songko.oauth2authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.songko.oauth2authserver.authentication.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * 첫 번째 시큐리티 필터 체인 : OAuth2 인증 서버의 보안 처리
     */
//    @Order(1)
//    @Bean
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        // 기본적인 OAuth2 보안을 적용
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        // OpenID Connect(OIDC)를 활성화하여 OpenID 기반의 인증 및 사용자 정보를 처리할 수 있도록 설정
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());
//
//        // 인증되지 않은 상태에서 Authorization Endpoint로 접근 시 로그인 페이지로 리다이렉트
//        http.exceptionHandling((exceptions) -> exceptions
//                .defaultAuthenticationEntryPointFor(
//                        new LoginUrlAuthenticationEntryPoint("/login"),
//                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                )
//        );
//
//        // OAuth2 리소스 서버 기능을 활성화하여 JWT 토큰을 통한 리소스 보호를 설정
//        http.oauth2ResourceServer((resourceServer) -> resourceServer
//                .jwt(Customizer.withDefaults()));
//
//        return http.build();
//    }
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer());

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims((claims) -> {
                    Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                            .stream()
                            .map(c -> c.replaceFirst("^ROLE_", ""))
                            .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                    claims.put("roles", roles);

                    claims.put(OAuth2ParameterNames.USERNAME, context.get(OAuth2ParameterNames.USERNAME));
                    claims.put(OAuth2ParameterNames.PASSWORD, context.get(OAuth2ParameterNames.PASSWORD));
                });
            }
        };
    }

    // Entry Point
    @Order(1)
    @Bean
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        // OAuth2AuthorizationServerConfigurer 설정
        // cf) OAuth2AuthorizationServerConfiguration.applyDefaultSecurity
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenRequestConverter(new SongkoGrantAuthenticationConverter())
                .authenticationProvider(new SongkoGrantAuthenticationProvider(authorizationService, tokenGenerator))
        );

        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenRequestConverter(new Oauth2PasswordCredentialsAuthenticationConverter())
                .authenticationProvider(new Oauth2PasswordCredentialsAuthenticationProvider(authorizationService, tokenGenerator))
        );


        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);

        // JWT 기반 리소스 서버 설정
        http.oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults()));

        // OpenID Connect 설정
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // 인증되지 않은 상태에서 Authorization Endpoint로 접근 시 로그인 페이지로 리다이렉트
        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        return http.build();
    }

    /**
     * 두 번째 시큐리티 필터 체인 : 기본적인 애플리케이션 보안 처리
     * - OAuth2 인증 서버와는 별도의 보안 설정을 처리
     */
    @Order(2)
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // 모든 요청에 대해 인증을 요구
        http.authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
        );

        // 폼 로그인이 Authorization 서버 필터 체인에서 로그인 페이지로 리다이렉트를 처리
        http.formLogin(Customizer.withDefaults());

        // CSRF 보호 비활성화
//        http.csrf(csrf -> csrf.disable());

        return http.build();
    }

    /**
     * 인메모리 사용자 정보를 관리하는 UserDetailsService 설정입니다.
     * - 간단한 사용자 정보를 메모리에 저장하고 관리합니다. (개발 또는 테스트 환경에서 유용)
     * - 실제 운영 환경에서는 데이터베이스 연동을 통해 사용자 관리를 해야 합니다.
     * - 기본 사용자로 username: "user", password: "password"를 설정하고, 역할은 "USER"로 지정합니다.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
    /**
     *
     * <code>
     curl -X POST http://localhost:8080/oauth2/device_authorization \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic $(echo -n 'oidc-client:secret' | base64)" \
     -d "scope=openid profile"
     * </code>
     */

    /**
     * 인메모리 클라이언트 저장소 설정입니다.
     * - OAuth2 또는 OIDC 클라이언트가 인증 서버에 등록될 수 있도록 설정합니다.
     * - 인메모리 방식으로 클라이언트 정보를 저장합니다. 개발 중에 사용하며, 운영 환경에서는 영구 저장소로 대체해야 합니다.
     * - 등록된 클라이언트가 Authorization Code, Refresh Token, Client Credentials 등의 인증 방식을 사용할 수 있도록 설정합니다.
     * - 리다이렉트 URI와 로그아웃 후 리다이렉트 URI 등을 설정하여 클라이언트의 리디렉션 동작을 정의합니다.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")  // 클라이언트 비밀
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)  // 인증 방법 (NONE, CLIENT_SECRET_BASIC, CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // 인증 코드 플로우
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)  // 리프레시 토큰 플로우
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // 클라이언트 자격 증명 플로우
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(CustomAuthorizationGrantType.SONGKO)
                .redirectUri("http://127.0.0.1:3000/login/oauth2/code/oidc-client")  // 리다이렉트 URI 설정
                .postLogoutRedirectUri("http://127.0.0.1:8080/")  // 로그아웃 후 리다이렉트 URI
                .scope(OidcScopes.OPENID)  // OpenID 스코프 설정
                .scope(OidcScopes.PROFILE)  // 프로필 스코프 설정
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())  // 클라이언트 설정
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                .clientSecret("{noop}secret")  // 클라이언트 비밀
//                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)  // 인증 방법 (NONE, CLIENT_SECRET_BASIC, CLIENT_SECRET_POST)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
////                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // 인증 코드 플로우
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)  // 리프레시 토큰 플로우
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // 클라이언트 자격 증명 플로우
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")  // 리다이렉트 URI 설정
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")  // 로그아웃 후 리다이렉트 URI
//                .scope(OidcScopes.OPENID)  // OpenID 스코프 설정
//                .scope(OidcScopes.PROFILE)  // 프로필 스코프 설정
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())  // 클라이언트 설정
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }

    /**
     * JWK 소스 설정
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // RSA 키 쌍을 생성. JWT 토큰의 서명 및 검증에 사용
        KeyPair keyPair = generateRsaKey();

        // 인증 서버에서 발급하는 JWT 토큰의 서명 및 검증에 사용될 공개키와 비공개키를 생성
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())  // 키 ID 생성
                .build();

        // JWK(Json Web Key) 형식으로 저장된 RSA 키는 클라이언트 및 리소스 서버에서 사용할 수 있도록 제공 됨.
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * RSA 키 생성
     * - 2048비트 길이의 RSA 키 쌍을 생성
     * - RSA는 비대칭 암호화 알고리즘으로, 공개키와 비공개키를 생성하여 암호화 및 서명에 사용
     * - 비공개키는 JWT 서명에 사용되며, 공개키는 서명된 JWT를 검증할 때 사용
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);  // 키 길이 2048비트
            keyPair = keyPairGenerator.generateKeyPair();  // RSA 키 쌍 생성
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * JWT 디코더 설정
     * - JWT를 디코딩하고 검증
     * - 발급된 JWT 토큰이 유효한지 확인하는 기능 제공
     * - 서명을 검증하고 토큰의 유효성을 판단
     * - JWK 소스를 통해 제공된 공개키를 사용하여 JWT의 서명을 검증
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }


    /**
     * 인증 서버의 기본 설정을 제공
     * - OAuth2 Authorization 서버의 기본적인 설정을 구성
     * - 기본 URI 설정 및 기타 설정들을 자동으로 구성
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
