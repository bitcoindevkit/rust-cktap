import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

group = "com.coinkite.cktap"
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
