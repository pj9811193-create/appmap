// Resolve plugins from Maven Central. The Gradle Plugin Portal redirects to a
// CDN (plugins-artifacts.gradle.org) that some restricted networks block.
pluginManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "appmap-kotlin"
