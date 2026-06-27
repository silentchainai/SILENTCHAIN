plugins {
    java
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.sn1persecurity.silentchain"
version = "1.3.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    implementation("org.json:json:20240303")

    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
    testImplementation("org.json:json:20240303")
    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Implementation-Title" to "SILENTCHAIN Community Edition",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Sn1persecurity LLC"
        )
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    archiveBaseName.set("silentchain-community-edition")
    minimize()
    mergeServiceFiles()
}

tasks.named("build") {
    dependsOn(tasks.shadowJar)
}
