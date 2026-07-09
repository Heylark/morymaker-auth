package kr.co.morymaker.auth.application.service.account

/** 이메일 중복(§3-2 email UNIQUE) — server-auth GlobalExceptionHandler가 409 EMAIL_DUPLICATE로 매핑. */
class EmailDuplicateException(email: String) : RuntimeException("이미 사용 중인 이메일입니다: $email")

/** 존재하지 않는 계정 id(§3-3·§3-4) — server-auth GlobalExceptionHandler가 404 NOT_FOUND로 매핑. */
class AccountNotFoundException(id: String) : RuntimeException("계정을 찾을 수 없습니다: $id")

/**
 * 역할별 행사할당 필수 위반(EVENT_ADMIN/EVENT_STAFF인데 eventIds가 비어있음) — server-auth
 * GlobalExceptionHandler가 422 BUSINESS_RULE로 매핑(spec §0-5 비즈니스 규칙 범주, 필드 형식
 * 오류인 400 VALIDATION_FAILED와 구분).
 */
class EventAssignmentRequiredException(role: String) :
    RuntimeException("$role 역할은 담당 행사가 최소 1개 필요합니다")
