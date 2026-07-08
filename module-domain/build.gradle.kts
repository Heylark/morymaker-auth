// module-domain/build.gradle.kts
// 순수 도메인 모듈 — Spring·Web·Persistence 무의존. 계정·권한 도메인 규칙이 이 모듈에 안착한다.
dependencies {
    // Jakarta Validation (compileOnly — 도메인 검증 애노테이션 참조용)
    compileOnly("jakarta.validation:jakarta.validation-api")

    // Jackson annotations (compileOnly — 직렬화 애노테이션 API 호환)
    compileOnly("com.fasterxml.jackson.core:jackson-annotations")
}
