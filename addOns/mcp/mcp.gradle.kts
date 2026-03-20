description = "An add-on that implements an MCP server in ZAP."

zapAddOn {
    addOnName.set("MCP Server")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.addon.mcp.ExtensionMcp")
        }
        dependencies {
            addOns {
                register("automation") {
                    version.set(">=0.59.0")
                }
                register("commonlib") {
                    version.set(">=1.17.0")
                }
                register("network") {
                    version.set(">=0.1.0")
                }
                register("pscan") {
                    version.set(">=0.6.0")
                }
                register("reports") {
                    version.set(">=0.44.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("pscan")
    zapAddOn("reports")

    testImplementation(project(":testutils"))
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
