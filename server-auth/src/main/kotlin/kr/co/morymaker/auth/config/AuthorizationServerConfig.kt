package kr.co.morymaker.auth.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

/**
 * 최소 in-memory Spring Authorization Server 부트 config — "빌드·기동되는 빈 골격" 완료 기준용.
 *
 * [OAuth2AuthorizationServerConfiguration] 을 import하면 기본 SecurityFilterChain(AS 엔드포인트 한정 보안 적용)과
 * AuthorizationServerSettings 기본값이 함께 등록된다 — 이 config가 직접 공급하는 빈은 RegisteredClientRepository·
 * JWKSource 두 가지뿐이며, 나머지는 프레임워크 기본값을 그대로 사용한다.
 *
 * 실 계정 도메인 이식·durable JDBC 저장·event_ids 클레임·MFA/SAML/SCIM 등은 이 config의 책임이 아니다 — 후속 REQ에서
 * 이 자리를 대체한다.
 */
@Configuration
@Import(OAuth2AuthorizationServerConfiguration::class)
class AuthorizationServerConfig {

    /**
     * 골격 기동 확인용 placeholder 클라이언트. 실 클라이언트 등록·발급 정책은 후속 REQ가 대체한다.
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val placeholderClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("morymaker-skeleton-client")
            .clientSecret("{noop}skeleton-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("skeleton.read")
            .build()
        return InMemoryRegisteredClientRepository(placeholderClient)
    }

    /**
     * 인메모리 RSA 키 1개로 JWK 소스를 구성한다. 프로세스 재기동 시 키가 바뀌므로 발급된 토큰은 재검증되지 않는다 —
     * 골격 기동 확인 용도로만 충분하며, 영속 키 관리는 후속 REQ.
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

        val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(UUID.randomUUID().toString())
            .build()

        return ImmutableJWKSet(JWKSet(rsaKey))
    }
}
