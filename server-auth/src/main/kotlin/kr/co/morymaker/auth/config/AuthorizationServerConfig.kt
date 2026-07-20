package kr.co.morymaker.auth.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.micrometer.core.instrument.MeterRegistry
import kr.co.morymaker.auth.application.port.out.refresh.ConsumedRefreshTokenPort
import kr.co.morymaker.auth.oauth2.HashedRefreshTokenAuthorizationService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcOperations
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

/**
 * Spring Authorization Server durable 배선 — 클라이언트·인가·동의를 전부 JDBC(MariaDB)에 저장한다.
 *
 * 골격 단계는 `@Import(OAuth2AuthorizationServerConfiguration)`로 기본 필터체인까지
 * 함께 등록했지만, [SecurityConfig]가 `@Order(1)` 체인을 직접 소유(`applyDefaultSecurity` 명시 호출)하게
 * 되면서 이 클래스는 순수하게 SAS 빈 공급만 담당한다. `@Import`를 유지한 채 빈만 JDBC로 바꿔도 동작은
 * 하지만, SecurityConfig가 폼 로그인(`@Order(5)`) 체인을 함께 소유하는 2체인 구조로 가려면 AS 필터체인도
 * 이 config가 아니라 SecurityConfig에서 명시적으로 구성해야 일관된다.
 */
@Configuration
class AuthorizationServerConfig(
    private val authProperties: AuthProperties,
) {

    /**
     * 인메모리 RSA 키 1개로 JWK 소스를 구성한다. 프로세스 재기동 시 키가 바뀌므로 재기동 전 발급된
     * access token은 재검증되지 않는다 — refresh token 검증은 DB 저장 해시(키 무관)라 재기동 후에도
     * 생존한다(재기동 시 access token만 재발급 필요). 단일 인스턴스 lite 배포에서 수용 가능한 트레이드오프이며,
     * JWKS 영속화(다중 인스턴스 대응)는 스케일아웃 시점에 재검토한다.
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

    /** 위 [jwkSource]에서 파생된 JWT decoder — access token 서명 검증용. */
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    /** BCrypt password encoder — 계정 비밀번호 해시(후속 Phase의 로그인에서 사용). */
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    /** AuthorizationServer 설정 — issuer URI를 설정값에서 가져온다(하드코딩 금지). */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder()
            .issuer(authProperties.issuer)
            .build()

    /**
     * durable 클라이언트 저장소 — `oauth2_registered_client` 테이블을 직접 사용한다(커스텀 매퍼 없음,
     * SAS 기본 `JdbcRegisteredClientRepository` 그대로). 빈 테이블로 시작하므로
     * [kr.co.morymaker.auth.bootstrap.RegisteredClientSeeder]가 기동 시 web 클라이언트를 멱등 등록한다.
     */
    @Bean
    fun registeredClientRepository(jdbcOperations: JdbcOperations): RegisteredClientRepository =
        JdbcRegisteredClientRepository(jdbcOperations)

    /**
     * durable 인가 저장(재기동 후에도 인가 코드/토큰 상태 보존) + refresh at-rest SHA-256 해시 +
     * 재사용 탐지·패밀리 무효화(rotation으로 교체된 옛 토큰 재제시 시 침해 신호로 간주해 같은 authorization의
     * 전체 토큰을 무효화) 세 결정이 이 Decorator 체인에 누적된다.
     *
     * SAS [JdbcOAuth2AuthorizationService]를 [HashedRefreshTokenAuthorizationService] Decorator로 감싸
     * refresh_token_value를 저장 시 해시·조회 시 역해시한다. SAS는 단일 [OAuth2AuthorizationService] 빈을
     * `getOptionalBean`으로 자동 탐지하므로, 이 Decorator만 인터페이스 빈으로 노출하면 추가 배선이 필요 없다.
     *
     * ## WHY — delegate(Jdbc)를 별도 @Bean으로 등록하지 않고 본문에서 inline 생성한다
     * [JdbcOAuth2AuthorizationService]는 [OAuth2AuthorizationService]를 **구현**한다. delegate를 별도 빈으로
     * 등록하면 SAS의 `getOptionalBean(OAuth2AuthorizationService.class)`(= `beansOfTypeIncludingAncestors`)가
     * delegate·Decorator **둘 다** 매칭해 `NoUniqueBeanDefinitionException`이 난다.
     * 반환 타입을 구체 타입으로 좁혀도 인터페이스 쿼리는 여전히 두 빈을 본다.
     * → delegate를 메서드 본문 지역 변수로 생성해 인터페이스 빈은 Decorator 1개만 남긴다.
     *
     * ## TransactionTemplate (record-before-overwrite 원자성)
     * [HashedRefreshTokenAuthorizationService]는 `@Bean new`로 직접 생성되므로 Spring AOP 프록시가
     * 감싸지 않아 `@Transactional` 어노테이션이 silent-ignore된다.
     * record-before-overwrite 원자성은 [TransactionTemplate]으로 프로그래매틱하게 보장한다.
     *
     * @param consumedPort  [ConsumedRefreshTokenPort] — consumed-hash DB 레지스트리(재기동 후에도 유지되도록 durable 저장 채택)
     * @param txManager     DataSourceTransactionManager(Spring Boot 자동 등록)
     * @param meterRegistry 비즈니스 메트릭 계측 — refresh family-kill/grace counter (비-빈 직접 생성 객체에 DI 전달)
     */
    @Bean
    fun authorizationService(
        jdbcOperations: JdbcOperations,
        registeredClientRepository: RegisteredClientRepository,
        consumedPort: ConsumedRefreshTokenPort,
        txManager: PlatformTransactionManager,
        meterRegistry: MeterRegistry,
    ): OAuth2AuthorizationService {
        val delegate = JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository)
        val txTemplate = TransactionTemplate(txManager)
        return HashedRefreshTokenAuthorizationService(delegate, consumedPort, txTemplate, meterRegistry)
    }

    /** durable OAuth2 동의 저장 — 재기동 후에도 사용자 동의 이력을 보존한다(InMemory 기각). */
    @Bean
    fun authorizationConsentService(
        jdbcOperations: JdbcOperations,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository)
}
