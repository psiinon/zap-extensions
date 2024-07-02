import org.zaproxy.gradle.addon.AddOnStatus

description = "Helps identify and set up authentication handling"

zapAddOn {
    addOnName.set("Authentication Helper")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/authentication-helper/")
        extensions {
            register("org.zaproxy.addon.authhelper.spiderajax.ExtensionAuthhelperAjax") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.authhelper.spiderajax"))
                }
                dependencies {
                    addOns {
                        register("spiderAjax") {
                            version.set(">=23.15.0")
                        }
                    }
                }
            }
            register("org.zaproxy.addon.authhelper.client.ExtensionAuthhelperClient") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.authhelper.client"))
                }
                dependencies {
                    addOns {
                        register("spiderAjax") {
                            version.set(">=23.15.0")
                        }
                        register("scripts") {
                            version.set(">=45.4.0")
                        }
                        register("zest") {
                            version.set(">=47")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.13.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">=0.6.0")
                }
                register("selenium") {
                    version.set("15.*")
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("selenium")
    zapAddOn("spiderAjax")
    zapAddOn("zest")

    implementation("org.zaproxy:zest:0.22.0") {
        // Provided by commonlib add-on.
        exclude(group = "com.fasterxml.jackson")
        // Provided by Selenium add-on.
        exclude(group = "org.seleniumhq.selenium")
        // Provided by ZAP.
        exclude(group = "net.htmlparser.jericho", module = "jericho-html")
    }

    testImplementation(project(":testutils"))
}
