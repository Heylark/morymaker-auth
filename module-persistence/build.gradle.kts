// module-persistence/build.gradle.kts
// JPA 전면 배제 — MyBatis 단독. plugin.jpa·kapt·querydsl-*·data-jpa 모두 미포함.
// spring-boot-starter-jdbc 포함 — SAS Jdbc* 저장소(JdbcRegisteredClientRepository 등)가 JdbcOperations를 요구하기 때문.
// server-auth가 이 모듈을 boot classpath에 배선해 durable 저장이 활성화된다.
dependencies {
    api(project(":module-application"))

    // Spring Boot JDBC (SAS Jdbc* 저장소 대비)
    api("org.springframework.boot:spring-boot-starter-jdbc")

    // MyBatis
    api("org.mybatis.spring.boot:mybatis-spring-boot-starter:3.0.3")

    // Flyway
    api("org.flywaydb:flyway-core")
    api("org.flywaydb:flyway-mysql")

    // MariaDB JDBC Driver (런타임 전용)
    runtimeOnly("org.mariadb.jdbc:mariadb-java-client:3.4.1")
}
