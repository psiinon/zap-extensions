version = "2"
description = "A simple extension example."

zapAddOn {
    addOnName.set("Simple Example")
    // zapVersion.set("2.9.0")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.10.0-20201111.162919-2")
}
