package kr.co.morymaker.auth.bootstrap

import kr.co.morymaker.auth.config.AuthProperties
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Component
import java.util.UUID

/**
 * 기동 시 web 클라이언트를 config 기준으로 등록·갱신한다(reconciling upsert) — durable
 * `RegisteredClientRepository`는 빈 테이블로 시작하므로, 이 seeder 없이는 authorization_code
 * 흐름 자체가 불가능하다(등록된 클라이언트가 없어 모든 인가 요청이 unknown_client로 거부됨).
 *
 * ## config-authoritative 멱등성 (insert-only에서 전환)
 * 이전 구현은 `findByClientId`로 존재 여부만 확인해 있으면 재등록을 skip하는 insert-only였다.
 * 그러나 lite 배포는 클라이언트 관리 콘솔이 stripped되어 있어 등록 후 클라이언트 설정을 바꿀 정당한
 * 런타임 경로가 없다 — config(`application.yml`)가 유일한 진실이어야 한다(config-authoritative).
 * 기존 행이 있으면 **id를 회수**해 현재 config로 재빌드한 뒤 무조건 `save()`한다.
 * `JdbcRegisteredClientRepository.save()`는 id가 이미 존재하면 UPDATE, 없으면 INSERT하므로 단일
 * 경로로 멱등 + 자가 정합이 성립한다 — TTL 튜닝이나 TokenSettings 변경 같은 config 수정이 재기동만으로
 * durable 행에 전파된다(수동 DB 수술 불요).
 *
 * ## client secret 인코딩
 * `morymaker.auth.web-client.client-secret` 설정값은 평문으로 두고, 이 seeder가 [passwordEncoder]로
 * 인코딩한 뒤 저장한다. `AuthorizationServerConfig.passwordEncoder()` 빈이 순수 BCrypt이므로
 * (`{noop}`/`{bcrypt}` 접두사로 알고리즘을 고르는 DelegatingPasswordEncoder가 아니다), 저장값도
 * 반드시 BCrypt 해시여야 클라이언트 인증(`client_secret_basic`) 시 비교가 성립한다.
 */
@Component
class RegisteredClientSeeder(
    private val registeredClientRepository: RegisteredClientRepository,
    private val passwordEncoder: PasswordEncoder,
    private val authProperties: AuthProperties,
) : ApplicationRunner {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun run(args: ApplicationArguments) {
        val webClient = authProperties.webClient
        val tokenPolicy = authProperties.tokenPolicy

        val existing = registeredClientRepository.findByClientId(webClient.clientId)
        val id = existing?.id ?: UUID.randomUUID().toString()

        val redirectUris = splitCsv(webClient.redirectUris)
        val scopes = splitCsv(webClient.scopes)

        val builder = RegisteredClient.withId(id)
            .clientId(webClient.clientId)
            .clientName(webClient.clientId)
            .clientSecret(passwordEncoder.encode(webClient.clientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .clientSettings(
                ClientSettings.builder()
                    // PKCE 필수 — confidential 클라이언트(client_secret_basic)라도 authorization_code
                    // 그랜트는 PKCE를 함께 요구해 code interception 공격 표면을 추가로 좁힌다.
                    .requireProofKey(true)
                    // 단일 first-party web 클라이언트(콘솔·실행자·키오스크·방문자 4표면 공용) — 동의 화면 불필요.
                    .requireAuthorizationConsent(false)
                    .build(),
            )
            .tokenSettings(
                TokenSettings.builder()
                    // reuseRefreshTokens=false는 config가 아닌 코드 하드코딩 — RFC 9700 §4.14.2 MUST
                    // 요구사항이자 재사용 탐지(HashedRefreshTokenAuthorizationService)가 성립하기 위한
                    // 전제(매 refresh마다 실제로 새 토큰이 발급돼야 oldHash != incomingHash가 성립한다).
                    // 이 값이 true(SAS 기본값)이면 SAS가 기존 토큰 객체(=DB에 저장된 at-rest 해시)를
                    // 그대로 재사용해 클라이언트에 반환 — 다음 refresh 요청이 재해시 불일치로 즉시 실패한다.
                    .reuseRefreshTokens(false)
                    .accessTokenTimeToLive(tokenPolicy.accessTokenTtl)
                    .refreshTokenTimeToLive(tokenPolicy.refreshTokenTtl)
                    .build(),
            )
        redirectUris.forEach { builder.redirectUri(it) }
        scopes.forEach { builder.scope(it) }

        registeredClientRepository.save(builder.build())
        if (existing == null) {
            log.info("web client seeded: clientId={}", webClient.clientId)
        } else {
            log.info("web client reconciled (config-authoritative): clientId={}", webClient.clientId)
        }
    }

    private fun splitCsv(value: String): List<String> =
        value.split(",").map { it.trim() }.filter { it.isNotEmpty() }
}
