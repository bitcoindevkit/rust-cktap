import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.dokka")
    id("com.vanniktech.maven.publish")
}

group = "org.bitcoindevkit"
version = "0.1.0-SNAPSHOT"

android {
    namespace = group.toString()
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }
}

tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// Fail fast if the Rust/UniFFI pipeline hasn't populated the generated Kotlin
// sources and native libraries. Without this, Gradle will happily assemble and
// publish an empty AAR from a clean checkout — see
// `scripts/release/build-release-*.sh` (or `scripts/dev/build-dev-*.sh`) for the
// step that must run first.
val verifyFfiArtifacts by tasks.registering {
    group = "verification"
    description = "Verifies generated Kotlin bindings and jniLibs exist before assembling the AAR."
    doLast {
        val kotlinSrc = file("src/main/kotlin")
        val jniLibs = file("src/main/jniLibs")
        val hasBindings = kotlinSrc.walkTopDown().any { it.isFile && it.extension == "kt" }
        val hasNative = jniLibs.walkTopDown().any { it.isFile && it.name == "libcktap_ffi.so" }
        if (!hasBindings || !hasNative) {
            throw GradleException(
                "Missing FFI artifacts. Run `just build <arch>` (release) or " +
                    "`just build-dev` from cktap-android/ before assembling or publishing.\n" +
                    "  kotlin bindings present: $hasBindings\n" +
                    "  libcktap_ffi.so present:  $hasNative"
            )
        }
    }
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(verifyFfiArtifacts)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("androidx.appcompat:appcompat:1.4.0")
    implementation("androidx.core:core-ktx:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    api("org.slf4j:slf4j-api:1.7.30")

    androidTestImplementation("com.github.tony19:logback-android:2.0.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.4.0")
    androidTestImplementation("org.jetbrains.kotlin:kotlin-test:1.6.10")
    androidTestImplementation("org.jetbrains.kotlin:kotlin-test-junit:1.6.10")
}

mavenPublishing {
    coordinates(
        groupId = group.toString(),
        artifactId = "cktap-android",
        version = version.toString()
    )

    pom {
        name.set("cktap-android")
        description.set("Coinkite Tap Protocol language bindings for Android.")
        url.set("https://github.com/bitcoindevkit/rust-cktap")
        inceptionYear.set("2025")
        licenses {
            license {
                name.set("APACHE 2.0")
                url.set("https://github.com/bitcoindevkit/rust-cktap/blob/master/LICENSE-APACHE")
            }
            license {
                name.set("MIT")
                url.set("https://github.com/bitcoindevkit/rust-cktap/blob/master/LICENSE-MIT")
            }
        }
        developers {
            developer {
                id.set("cktapdevelopers")
                name.set("rust-cktap developers")
                email.set("dev@bitcoindevkit.org")
            }
        }
        scm {
            url.set("https://github.com/bitcoindevkit/rust-cktap/")
            connection.set("scm:git:github.com/bitcoindevkit/rust-cktap.git")
            developerConnection.set("scm:git:ssh://github.com/bitcoindevkit/rust-cktap.git")
        }
    }

    configure(
        AndroidSingleVariantLibrary(
            javadocJar = JavadocJar.Dokka("dokkaGeneratePublicationHtml"),
            sourcesJar = SourcesJar.Sources(),
            variant = "release",
        )
    )

    publishToMavenCentral()
    // Signing is only applied when NOT in localBuild mode AND GPG props are present.
    // This keeps local development fully functional without any credentials.
    // To enable signing (for Maven Central release), add to ~/.gradle/gradle.properties:
    //   signing.gnupg.keyName=<GPG_KEY_ID>
    //   signing.gnupg.passphrase=<GPG_PASSPHRASE>
    if (!project.hasProperty("localBuild")
        && project.findProperty("signing.gnupg.keyName") != null
    ) {
        signAllPublications()
    }
}

dokka {
    moduleName.set("cktap-android")
    moduleVersion.set(version.toString())
    dokkaSourceSets.main {
        includes.from("../docs/DOKKA_LANDING.md")
        sourceLink {
            localDirectory.set(file("src/main/kotlin"))
            remoteUrl("https://github.com/bitcoindevkit/rust-cktap")
            remoteLineSuffix.set("#L")
        }
    }
    pluginsConfiguration.html {
        footerMessage.set("(c) rust-cktap Developers")
    }
}
