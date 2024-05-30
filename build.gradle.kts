plugins { id("io.vacco.oss.gitflow") version "0.9.8" }

group = "io.vacco.jwt"
version = "0.8.0"

configure<io.vacco.oss.gitflow.GsPluginProfileExtension> {
  addJ8Spec()
  sharedLibrary(true, false)
}

dependencies {
  testImplementation("com.google.code.gson:gson:2.10.1")
}
