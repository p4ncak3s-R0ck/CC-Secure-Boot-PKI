plugins {
    java
    kotlin("jvm") version "2.0.20"
    id("net.neoforged.moddev") version "2.0.42-beta"
}

version = project.property("mod_version").toString()
group = "cc.p4ncak3s_r0ck.ccsecurebootpki"

base {
    archivesName = "CCSecureBootPKI"
}

java.toolchain.languageVersion = JavaLanguageVersion.of(21)

neoForge {
    version = property("neoforge_version") as String

    runs {
        register("client") { client() }
        register("server") { server() }
    }

    mods {
        register("ccsecurebootpki") {
            sourceSet(sourceSets.main.get())
        }
    }
}

tasks.processResources {
    val replaceProperties = mapOf(
        "mod_version" to project.property("mod_version").toString()
    )

    inputs.properties(replaceProperties)

    filesMatching("META-INF/neoforge.mods.toml") {
        expand(replaceProperties)
    }
}

repositories {
    mavenCentral()
    maven("https://modmaven.dev/")
    maven("https://maven.squiddev.cc") {
        content { includeGroup("cc.tweaked") }
    }
}

dependencies {
    compileOnly("cc.tweaked:cc-tweaked-1.21.1-forge-api:1.119.0")
    compileOnly("org.jspecify:jspecify:1.0.0")
    compileOnly("org.bouncycastle:bcprov-jdk18on:1.81")
    compileOnly("org.bouncycastle:bcpkix-jdk18on:1.81")
    compileOnly("org.bouncycastle:bcutil-jdk18on:1.81")
    jarJar("org.bouncycastle:bcprov-jdk18on:1.81")
    jarJar("org.bouncycastle:bcpkix-jdk18on:1.81")
    jarJar("org.bouncycastle:bcutil-jdk18on:1.81")
}
