plugins {
    // Auto-provisions the JDK 21 toolchain on build hosts that do not have one installed.
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "silentchain-for-burp-ai"
