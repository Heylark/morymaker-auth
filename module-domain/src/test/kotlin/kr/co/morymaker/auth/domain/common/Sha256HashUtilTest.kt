package kr.co.morymaker.auth.domain.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * [Sha256HashUtil] 단위 테스트.
 *
 * known vector("hello")는 외부 도구(`echo -n hello | sha256sum`)로도 검증 가능.
 */
class Sha256HashUtilTest {

    @Test
    fun `hash 는 known SHA-256 hex 64자를 생성한다`() {
        val result = Sha256HashUtil.hash("hello")

        // echo -n "hello" | sha256sum → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            result,
            "SHA-256(\"hello\") lowercase hex와 byte-identical 해야 함",
        )
        assertEquals(64, result.length, "SHA-256 hex는 64자")
        assertTrue(result.all { it in '0'..'9' || it in 'a'..'f' }, "lowercase hex만 포함")
    }

    @Test
    fun `hash 는 결정적이다 — 같은 입력은 항상 같은 출력`() {
        val input = "high-entropy-token-abc123xyz"
        assertEquals(Sha256HashUtil.hash(input), Sha256HashUtil.hash(input))
    }

    @Test
    fun `hash 는 다른 입력에 대해 다른 결과를 반환한다`() {
        // 충돌 저항 기본 확인 (완전한 충돌 저항은 SHA-256 스펙이 보장)
        val h1 = Sha256HashUtil.hash("token-A")
        val h2 = Sha256HashUtil.hash("token-B")
        assertTrue(h1 != h2, "서로 다른 입력은 서로 다른 해시 출력")
    }
}
