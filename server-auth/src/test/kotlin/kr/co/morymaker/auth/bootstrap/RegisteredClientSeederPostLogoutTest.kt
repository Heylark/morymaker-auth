package kr.co.morymaker.auth.bootstrap

import kr.co.morymaker.auth.config.AuthProperties
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LogEvent
import org.apache.logging.log4j.core.Logger
import org.apache.logging.log4j.core.appender.AbstractAppender
import org.apache.logging.log4j.core.config.Property
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.DefaultApplicationArguments
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.annotation.DirtiesContext

/** 이 테스트 전용 in-memory 캡처 appender — 별도 test-jar 의존성 없이 log4j-core API만으로 구성한다. */
private class CapturingAppender : AbstractAppender(
    "RegisteredClientSeederPostLogoutTest-Capture",
    null,
    null,
    false,
    Property.EMPTY_ARRAY,
) {
    val events = mutableListOf<LogEvent>()

    override fun append(event: LogEvent) {
        events.add(event.toImmutable())
    }
}

/**
 * REQ-0045 — [RegisteredClientSeeder]의 post-logout 등록 동작 검증(설계 §5 V5·V11-b).
 *
 * V5: seeder 기동 후 DB `oauth2_registered_client.post_logout_redirect_uris`에 config 값이
 *     그대로 반영된다.
 * V11-b(v2 신설): 비정규 형태(끝 슬래시) post-logout URI는 등록은 그대로 되지만 WARN 로그가
 *     남는다 — 정규 URI는 WARN이 없다(대조군, 같은 실행에서 함께 검증).
 *
 * ## 왜 별도 프로퍼티 오버라이드 컨텍스트인가
 * 기본 컨텍스트의 `post-logout-redirect-uris`(application.yml 기본값)에는 끝 슬래시 URI가
 * 없어 비정규 경고를 재현할 수 없다 — `@SpringBootTest(properties=...)`로 끝 슬래시 URI 1개를
 * 추가한 별도 컨텍스트를 띄운다.
 *
 * ## 왜 애플리케이션 부팅 시점의 ApplicationRunner 실행을 그대로 캡처하지 않는가
 * 최초 시도는 `@BeforeAll`에서 appender를 미리 붙여 컨텍스트 refresh 중 실행되는
 * `ApplicationRunner.run()`의 로그를 캡처하려 했으나, Spring Boot의 `LoggingApplicationListener`가
 * `SpringApplication.run()` 초입에 로깅 시스템을 (재)초기화하면서 프로그래밍적으로 붙인 appender를
 * 함께 날려버려 캡처가 0건이 됐다(실측 — WARN·INFO 포함 전량 미캡처). 로깅 시스템 초기화가 끝난
 * *이후*(= 테스트 메서드 시점, 컨텍스트가 이미 떠 있는 상태)에 appender를 붙이고, 동일 seeder
 * 빈의 `run()`을 **직접 재호출**하는 방식으로 우회한다 — seeder는 config-authoritative
 * upsert라 여러 번 호출해도 멱등(같은 결과로 수렴)하므로 재호출 자체가 검증 대상 동작을 왜곡하지
 * 않는다.
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다.
 */
@SpringBootTest(
    properties = [
        // 끝 슬래시(비정규) 1개 + 정규 1개를 함께 등록해 같은 실행에서 양성·대조군을 동시에 확보한다.
        "morymaker.auth.web-client.post-logout-redirect-uris=" +
            "http://localhost:3000/app/logged-out/,http://localhost:3100/app/logged-out",
    ],
)
@DirtiesContext
class RegisteredClientSeederPostLogoutTest {

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    private lateinit var authProperties: AuthProperties

    @Autowired
    private lateinit var registeredClientSeeder: RegisteredClientSeeder

    private val capturingAppender = CapturingAppender()
    private lateinit var log4jLogger: Logger

    @BeforeEach
    fun attachAppender() {
        log4jLogger = LogManager.getLogger(RegisteredClientSeeder::class.java) as Logger
        capturingAppender.start()
        log4jLogger.addAppender(capturingAppender)
    }

    @AfterEach
    fun detachAppender() {
        log4jLogger.removeAppender(capturingAppender)
        capturingAppender.stop()
    }

    @Test
    fun `V5 - seeder 기동 후 DB post_logout_redirect_uris에 config 값이 그대로 반영된다`() {
        val stored = jdbcTemplate.queryForObject(
            "SELECT post_logout_redirect_uris FROM oauth2_registered_client WHERE client_id = ?",
            String::class.java,
            authProperties.webClient.clientId,
        )
        assertTrue(
            stored!!.contains("http://localhost:3000/app/logged-out/"),
            "★ 핵심 회귀 가드: DB 등록값에 config의 끝 슬래시 URI가 그대로 반영돼야 함 — 실제 저장값=$stored",
        )
        assertTrue(stored.contains("http://localhost:3100/app/logged-out"), "정규 URI도 함께 등록돼야 함 — 실제 저장값=$stored")
    }

    @Test
    fun `V11-b - 비정규(끝 슬래시) post-logout URI는 WARN 로그가 남는다`() {
        registeredClientSeeder.run(DefaultApplicationArguments())

        val warnMessages = capturingAppender.events
            .filter { it.level == Level.WARN }
            .map { it.message.formattedMessage }

        assertTrue(
            warnMessages.any {
                it.contains("비정규") && it.contains("http://localhost:3000/app/logged-out/")
            },
            "★ 핵심 회귀 가드: 끝 슬래시 URI는 '비정규' WARN 로그를 남겨야 함 — 실제 WARN 목록=$warnMessages",
        )
    }

    @Test
    fun `V11-b 대조군 - 정규 URI(끝 슬래시 없음)는 비정규 WARN이 없다`() {
        registeredClientSeeder.run(DefaultApplicationArguments())

        val warnMessages = capturingAppender.events
            .filter { it.level == Level.WARN }
            .map { it.message.formattedMessage }

        assertFalse(
            warnMessages.any {
                it.contains("비정규") && it.contains("http://localhost:3100/app/logged-out") &&
                    !it.contains("http://localhost:3100/app/logged-out/")
            },
            "정규 URI(끝 슬래시 없음)는 비정규 WARN 대상이 아니어야 함 — 실제 WARN 목록=$warnMessages",
        )
    }
}
