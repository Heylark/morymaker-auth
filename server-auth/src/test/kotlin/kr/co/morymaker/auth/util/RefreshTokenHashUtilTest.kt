package kr.co.morymaker.auth.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import java.util.Base64

/**
 * [RefreshTokenHashUtil] 단위 테스트 — refresh token을 at-rest 상태로 SHA-256 해시 저장해 DB 탈취 시에도 원문이 노출되지 않게 한다.
 *
 * 순수 함수라 Spring context·DB가 필요 없다 (POJO unit test — 빠른 보안 회귀 차단).
 */
class RefreshTokenHashUtilTest {

    /**
     * hash()는 SHA-256 lowercase hex 64자를 생성한다.
     *
     * known vector: `"hello"`의 SHA-256은 잘 알려진 값이라 외부 도구(`echo -n hello | sha256sum`)와 대조 가능.
     */
    @Test
    fun `hash 는 known SHA-256 hex 64자를 생성한다`() {
        val hashed = RefreshTokenHashUtil.hash("hello")

        // echo -n "hello" | sha256sum → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            hashed,
            "SHA-256(\"hello\") lowercase hex와 byte-identical 해야 함",
        )
        assertEquals(64, hashed.length, "SHA-256 hex는 64자")
        assertTrue(hashed.all { it in '0'..'9' || it in 'a'..'f' }, "lowercase hex만 포함")
    }

    /**
     * hash()는 결정적(deterministic) — 같은 입력은 항상 같은 출력.
     * (조회 시 입력 토큰을 해시해 컬럼과 비교하는 lookup 계약이 성립하려면 필수.)
     */
    @Test
    fun `hash 는 결정적이다`() {
        val token = "some-refresh-token-value-abc123"
        assertEquals(RefreshTokenHashUtil.hash(token), RefreshTokenHashUtil.hash(token))
    }

    /**
     * isHashed()는 자신의 해시 출력에 대해 true를 반환한다 (멱등 가드 positive).
     */
    @Test
    fun `isHashed 는 hash 출력에 대해 true`() {
        val hashed = RefreshTokenHashUtil.hash("any-raw-token")
        assertTrue(RefreshTokenHashUtil.isHashed(hashed), "자신의 해시 출력은 isHashed=true 여야 함")
    }

    /**
     * ★ 보안 회귀 차단:
     * **실제 SAS가 발급하는 refresh token 포맷은 절대 isHashed=false** 여야 한다.
     *
     * ## WHY — 이 음성 테스트가 가장 중요한 이유
     * 멱등 가드의 보안 정확성은 "SAS raw 토큰이 절대 `^[0-9a-f]{64}$`에 매칭 안 됨" 가정에 의존한다.
     * 만약 미래에 tokenGenerator가 hex 형태 토큰을 발급하도록 바뀌면, 가드가 raw 토큰을 "이미 해시됨"으로
     * 오판해 **평문 저장**하는 실제 보안 회귀가 발생한다. 그 회귀를 잡아내는 유일한 테스트가 이것이다
     * (positive hash 벡터 테스트는 이 음성 케이스를 커버하지 못한다).
     *
     * SAS 기본 refresh token generator(`Base64StringKeyGenerator(urlEncoder no-pad, 96 bytes)`)와
     * 동일 설정으로 100개를 발급해 전부 isHashed=false 임을 확인한다.
     */
    @Test
    fun `isHashed 는 실제 SAS refresh token 포맷에 대해 false`() {
        // SAS OAuth2RefreshTokenGenerator 와 동일 설정 (urlEncoder withoutPadding, 96 bytes)
        val sasRefreshTokenGenerator = Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 96,
        )

        repeat(100) {
            val realSasToken = sasRefreshTokenGenerator.generateKey()
            assertFalse(
                RefreshTokenHashUtil.isHashed(realSasToken),
                "실제 SAS refresh token($realSasToken)이 isHashed=true 면 가드가 raw를 평문 저장함 — 보안 회귀",
            )
        }
    }

    /**
     * isHashed()는 64자가 아니거나 hex 외 문자가 섞이면 false (경계 케이스).
     */
    @Test
    fun `isHashed 는 비-해시 형식에 대해 false`() {
        assertFalse(RefreshTokenHashUtil.isHashed(""), "빈 문자열")
        assertFalse(RefreshTokenHashUtil.isHashed("abc"), "너무 짧음")
        assertFalse(RefreshTokenHashUtil.isHashed("g".repeat(64)), "hex 외 문자(g) 64자")
        assertFalse(RefreshTokenHashUtil.isHashed("A".repeat(64)), "대문자 hex 64자 (lowercase 강제)")
        assertFalse(RefreshTokenHashUtil.isHashed("a".repeat(63)), "63자 (64 미만)")
        assertFalse(RefreshTokenHashUtil.isHashed("a".repeat(65)), "65자 (64 초과)")
    }
}
