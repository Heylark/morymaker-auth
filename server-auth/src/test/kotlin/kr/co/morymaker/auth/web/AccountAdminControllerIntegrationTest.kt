package kr.co.morymaker.auth.web

import com.nimbusds.jose.proc.SecurityContext as NimbusSecurityContext
import com.nimbusds.jose.jwk.source.JWKSource
import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.config.AuthProperties
import kr.co.morymaker.auth.domain.account.Account
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

/**
 * `/api/accounts`(§3 어드민 CRUD) 실 DB·실 HTTP·실 서명 JWT 통합 테스트.
 *
 * Developer 단위 테스트(mockk — [kr.co.morymaker.auth.application.service.account.AccountAdminServiceTest]
 * 등 92건)는 서비스 로직 분기를 이미 검증했다. 이 클래스는 mock이 **우회하는 층**만 신규 검증한다:
 * - MyBatis 실 SQL(email UNIQUE 2중 방어, delete-insert 잔존 행, BCrypt 실 저장)
 * - Spring Security 실 필터체인(`AdminApiSecurityConfig`의 `hasRole` 게이트 enforcement)
 * - 실 서명 JWT의 `roles` claim → `ROLE_` authority 변환이 실제로 인가 결과에 반영되는지
 *
 * ## 실 서명 JWT를 사용하는 이유 — `SecurityMockMvcRequestPostProcessors.jwt()` 미사용
 * 그 postprocessor는 `.authorities(...)`로 지정한 권한을 SecurityContext에 직접 주입해 실
 * `AdminApiSecurityConfig.jwtAuthenticationConverter()`(roles→ROLE_ 변환, 인가 체인에서 가장
 * load-bearing한 부분)를 우회한다. 이 클래스는 [jwkSource] 빈으로 실제 서명한 JWT를 `Authorization`
 * 헤더에 실어 실 `JwtDecoder`→실 컨버터→실 `hasRole` 게이트 전 구간을 경유시킨다. 컨버터 자체의 claim
 * 변환 단위 검증은 [kr.co.morymaker.auth.config.AdminApiSecurityConfigTest]가 이미 담당한다(관심사 분리).
 *
 * `@Transactional`: 각 테스트가 삽입한 행은 종료 시 자동 롤백([kr.co.morymaker.auth.LoginFlowIntegrationTest]와
 * 동일 컨벤션) — 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AccountAdminControllerIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    private lateinit var jwkSource: JWKSource<NimbusSecurityContext>

    @Autowired
    private lateinit var authProperties: AuthProperties

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var accountPort: AccountPort

    @Autowired
    private lateinit var authenticationConfiguration: AuthenticationConfiguration

    private val authenticationManager: AuthenticationManager
        get() = authenticationConfiguration.authenticationManager

    private val jwtEncoder by lazy { NimbusJwtEncoder(jwkSource) }

    /** 실 서명 access token 발급 — [kr.co.morymaker.auth.config.TokenCustomizerConfig]가 실제로 만드는 `roles` claim(List<String>) 형태를 그대로 재현한다. */
    private fun accessToken(subject: String = UUID.randomUUID().toString(), vararg roles: String): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder()
            .issuer(authProperties.issuer)
            .subject(subject)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(1800))
            .claim("roles", roles.toList())
            .claim("authorities", emptyList<String>())
            .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).build()
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }

    private fun bearer(vararg roles: String): String = "Bearer " + accessToken(roles = roles)

    private fun seedAccount(
        email: String,
        role: String = "EVENT_STAFF",
        status: String = Account.STATUS_ACTIVE,
        rawPassword: String = "correct-horse-battery-staple",
    ): String {
        val id = UUID.randomUUID().toString()
        jdbcTemplate.update(
            """
            INSERT INTO account
                (id, email, name, role, password_hash, failed_attempts, locked_at, locked_until, status, created_at)
            VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
            """.trimIndent(),
            id, email, "테스트 계정", role, passwordEncoder.encode(rawPassword), status, Timestamp.from(Instant.now()),
        )
        return id
    }

    private fun accountEventCount(accountId: String): Int =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM account_event WHERE account_id = ?",
            Int::class.java,
            accountId,
        ) ?: 0

    // ── AUTHZ ──

    @Test
    fun `AUTHZ-001 토큰 없이 목록 조회하면 401 UNAUTHENTICATED`() {
        mockMvc.perform(get("/api/accounts"))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"))
    }

    @Test
    fun `AUTHZ-002 EVENT_ADMIN 토큰으로 목록 조회하면 403 ROLE_FORBIDDEN`() {
        mockMvc.perform(get("/api/accounts").header("Authorization", bearer("EVENT_ADMIN")))
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error.code").value("ROLE_FORBIDDEN"))
    }

    @Test
    fun `AUTHZ-003 EVENT_STAFF 토큰으로 목록 조회하면 403 ROLE_FORBIDDEN`() {
        mockMvc.perform(get("/api/accounts").header("Authorization", bearer("EVENT_STAFF")))
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error.code").value("ROLE_FORBIDDEN"))
    }

    @Test
    fun `AUTHZ-004 SYSTEM_ADMIN 토큰으로 목록 조회하면 200 (roles claim 실 서명 왕복 성공)`() {
        mockMvc.perform(get("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN")))
            .andExpect(status().isOk)
    }

    // ── email 중복 2중 방어 ──

    @Test
    fun `EMAIL-001 서비스 pre-check가 동일 이메일 재요청을 409 EMAIL_DUPLICATE 로 막는다`() {
        seedAccount(email = "dup-precheck@morymaker.co.kr")

        val body = """
            {"email":"dup-precheck@morymaker.co.kr","role":"EVENT_STAFF","eventIds":["event-1"],"password":"password123"}
        """.trimIndent()

        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error.code").value("EMAIL_DUPLICATE"))
    }

    @Test
    fun `EMAIL-002 pre-check 우회 시에도 DB UNIQUE 제약이 두번째 insert 를 DuplicateKeyException 으로 막는다 (동시성 최종 방어)`() {
        val email = "dup-dbunique@morymaker.co.kr"
        val first = Account(
            id = UUID.randomUUID().toString(), email = email, name = "첫 계정", role = "EVENT_STAFF",
            status = Account.STATUS_ACTIVE, passwordHash = passwordEncoder.encode("password123"),
            failedAttempts = 0, lockedAt = null, lockedUntil = null, note = null, createdAt = Instant.now(),
        )
        accountPort.insert(first)

        val second = Account(
            id = UUID.randomUUID().toString(), email = email, name = "두번째 계정(pre-check 우회)", role = "EVENT_STAFF",
            status = Account.STATUS_ACTIVE, passwordHash = passwordEncoder.encode("password123"),
            failedAttempts = 0, lockedAt = null, lockedUntil = null, note = null, createdAt = Instant.now(),
        )

        assertThrows(DuplicateKeyException::class.java) { accountPort.insert(second) }
    }

    // ── 역할별 eventIds 검증 ──

    @Test
    fun `ROLE-001 EVENT_ADMIN role 인데 eventIds 가 비어있으면 422 BUSINESS_RULE`() {
        val body = """{"email":"role-admin-empty@morymaker.co.kr","role":"EVENT_ADMIN","eventIds":[],"password":"password123"}"""

        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isUnprocessableEntity)
            .andExpect(jsonPath("$.error.code").value("BUSINESS_RULE"))
    }

    @Test
    fun `ROLE-002 EVENT_STAFF role 인데 eventIds 가 비어있으면 422 BUSINESS_RULE`() {
        val body = """{"email":"role-staff-empty@morymaker.co.kr","role":"EVENT_STAFF","eventIds":[],"password":"password123"}"""

        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isUnprocessableEntity)
            .andExpect(jsonPath("$.error.code").value("BUSINESS_RULE"))
    }

    @Test
    fun `ROLE-003 SYSTEM_ADMIN role 로 생성하면 eventIds 입력이 무시되고 account_event 행이 0건이다`() {
        val body = """
            {"email":"role-sysadmin@morymaker.co.kr","role":"SYSTEM_ADMIN","eventIds":["e1","e2"],"password":"password123"}
        """.trimIndent()

        val result = mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.data.eventIds").isEmpty)
            .andReturn()

        val id = jdbcTemplate.queryForObject(
            "SELECT id FROM account WHERE email = ?", String::class.java, "role-sysadmin@morymaker.co.kr",
        )
        assertEquals(0, accountEventCount(id!!))
        assertTrue(result.response.contentAsString.contains("\"eventIds\":[]"))
    }

    // ── 계정 CRUD ──

    @Test
    fun `CRUD-001 생성 성공 시 201, DB에는 BCrypt 해시가 저장되고 응답엔 비밀번호가 없다`() {
        val body = """
            {"email":"create-ok@morymaker.co.kr","name":"실행자","role":"EVENT_STAFF","eventIds":["event-1"],"note":"정문","password":"password123"}
        """.trimIndent()

        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.data.email").value("create-ok@morymaker.co.kr"))
            .andExpect(jsonPath("$.data.eventIds[0]").value("event-1"))
            .andExpect(jsonPath("$.data.password").doesNotExist())
            .andExpect(jsonPath("$.data.passwordHash").doesNotExist())
            .andExpect(jsonPath("$.data.initialPassword").doesNotExist())

        val hash = jdbcTemplate.queryForObject(
            "SELECT password_hash FROM account WHERE email = ?", String::class.java, "create-ok@morymaker.co.kr",
        )
        assertNotEquals("password123", hash)
        assertTrue(passwordEncoder.matches("password123", hash), "저장된 해시가 원본 비밀번호와 BCrypt matches 되어야 함")
    }

    @Test
    fun `CRUD-002 생성 시 비밀번호가 8자 미만이면 400 VALIDATION_FAILED`() {
        val body = """{"email":"short-pw@morymaker.co.kr","role":"EVENT_STAFF","eventIds":["event-1"],"password":"short1"}"""

        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(body),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error.code").value("VALIDATION_FAILED"))
    }

    @Test
    fun `CRUD-003 목록 조회는 role status q 필터와 meta(total page size) 를 반환한다`() {
        seedAccount(email = "list-admin@morymaker.co.kr", role = "EVENT_ADMIN")
        seedAccount(email = "list-staff@morymaker.co.kr", role = "EVENT_STAFF")

        mockMvc.perform(
            get("/api/accounts")
                .param("role", "EVENT_ADMIN")
                .param("q", "list-admin")
                .header("Authorization", bearer("SYSTEM_ADMIN")),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.length()").value(1))
            .andExpect(jsonPath("$.data[0].email").value("list-admin@morymaker.co.kr"))
            .andExpect(jsonPath("$.meta.total").value(1))
            .andExpect(jsonPath("$.meta.page").value(1))
    }

    @Test
    fun `CRUD-004 수정 시 역할 변경으로 account_event 가 delete-insert 로 전량 재작성된다 (잔존 0건)`() {
        val eventOld = "event-old"
        val eventNew1 = "event-new-1"
        val eventNew2 = "event-new-2"
        val createBody = """
            {"email":"rewrite@morymaker.co.kr","role":"EVENT_STAFF","eventIds":["$eventOld"],"password":"password123"}
        """.trimIndent()
        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(createBody),
        ).andExpect(status().isCreated)

        val id = jdbcTemplate.queryForObject(
            "SELECT id FROM account WHERE email = ?", String::class.java, "rewrite@morymaker.co.kr",
        )!!
        assertEquals(1, accountEventCount(id))

        val updateBody = """
            {"name":"개명","role":"EVENT_ADMIN","eventIds":["$eventNew1","$eventNew2"],"note":null}
        """.trimIndent()
        mockMvc.perform(
            put("/api/accounts/$id").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(updateBody),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.eventIds.length()").value(2))

        val remainingEventIds = jdbcTemplate.queryForList(
            "SELECT event_id FROM account_event WHERE account_id = ?", String::class.java, id,
        )
        assertEquals(setOf(eventNew1, eventNew2), remainingEventIds.toSet(), "구 event 잔존 0건 + 신규 event만 존재")
        assertFalse(remainingEventIds.contains(eventOld), "역할 변경 전 event가 delete 되지 않고 잔존하면 안 됨")
    }

    @Test
    fun `CRUD-005 존재하지 않는 id 를 수정하면 404 NOT_FOUND`() {
        val updateBody = """{"name":"없음","role":"EVENT_STAFF","eventIds":["event-1"]}"""

        mockMvc.perform(
            put("/api/accounts/no-such-id").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(updateBody),
        )
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.error.code").value("NOT_FOUND"))
    }

    @Test
    fun `CRUD-006 상태토글로 활성에서 비활성으로 전환된다`() {
        val id = seedAccount(email = "toggle@morymaker.co.kr", status = Account.STATUS_ACTIVE)

        mockMvc.perform(
            put("/api/accounts/$id/status").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content("""{"status":"비활성"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.status").value("비활성"))

        val status = jdbcTemplate.queryForObject("SELECT status FROM account WHERE id = ?", String::class.java, id)
        assertEquals("비활성", status)
    }

    @Test
    fun `CRUD-007 상태값이 활성 비활성이 아니면 400 VALIDATION_FAILED`() {
        val id = seedAccount(email = "toggle-invalid@morymaker.co.kr")

        mockMvc.perform(
            put("/api/accounts/$id/status").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content("""{"status":"UNKNOWN"}"""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error.code").value("VALIDATION_FAILED"))
    }

    @Test
    fun `CRUD-008 존재하지 않는 id 상태토글 시 404 NOT_FOUND`() {
        mockMvc.perform(
            put("/api/accounts/no-such-id/status").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content("""{"status":"비활성"}"""),
        )
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.error.code").value("NOT_FOUND"))
    }

    // ── 비활성 로그인 차단 연동 ──

    @Test
    fun `INACTIVE-001 어드민 API로 비활성화된 계정은 로그인 시 DisabledException (CustomUserDetailsService enabled 연동)`() {
        val createBody = """
            {"email":"inactive-flow@morymaker.co.kr","role":"EVENT_STAFF","eventIds":["event-1"],"password":"password123"}
        """.trimIndent()
        mockMvc.perform(
            post("/api/accounts").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(createBody),
        ).andExpect(status().isCreated)

        val id = jdbcTemplate.queryForObject(
            "SELECT id FROM account WHERE email = ?", String::class.java, "inactive-flow@morymaker.co.kr",
        )!!

        mockMvc.perform(
            put("/api/accounts/$id/status").header("Authorization", bearer("SYSTEM_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content("""{"status":"비활성"}"""),
        ).andExpect(status().isOk)

        assertThrows(DisabledException::class.java) {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken("inactive-flow@morymaker.co.kr", "password123"),
            )
        }
    }
}
