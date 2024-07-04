plugins { id("io.vacco.oss.gitflow") version "1.0.1" }

group = "io.vacco.jwt"
version = "0.8.0"

configure<io.vacco.oss.gitflow.GsPluginProfileExtension> {
  addJ8Spec()
  sharedLibrary(true, false)
}

dependencies {
  testImplementation("com.google.code.gson:gson:2.10.1")
}
