import org.zaproxy.gradle.addon.AddOnStatus

description = "Test apps and integration tests for the LLM add-on. Never released."

zapAddOn {
    addOnName.set("LLM Test Add-on")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")

        dependencies {
            addOns {
                register("dev") {
                    version.set(">=0.11.0")
                }
                register("llm") {
                    version.set(">=0.1.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("dev")
    zapAddOn("llm")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}
