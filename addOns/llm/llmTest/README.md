# LLM test add-on

Test apps and integration tests for the LLM add-on. This add-on is **never released**: it is marked
`zap.test.addon=true`, and the build fails if it is set up to be released or if another add-on
depends on it. See the Dev add-on help for how test add-ons work.

It needs the Dev add-on and ZAP running in dev mode (`-dev`).

## Fake LLM

An OpenAI compatible endpoint, `http://localhost:9091/llm/fake/v1`, which replies using regex rules.
Add an `OpenAI Compatible` provider to the LLM add-on with that endpoint, any model name and no API
key.

The rules are in `llm/fake/rules.json` in the `dev-add-on` directory under the ZAP home. It is a JSON
array of `match` (a case insensitive regex, searched for in the last user message) and `reply`
(a string, or a JSON object which is sent as a string). The first match wins. The file is re-read
on every request.

### Rule sets for other add-ons

An add-on's test add-on can provide its own rules, which do not affect other users of the fake LLM.
A rule set called `name` is used with the endpoint `http://localhost:9091/llm/fake/<name>/v1`, and
an unknown name gets a 404. There are two ways to provide one:

* Include the file `src/main/zapHomeFiles/dev-add-on/llm/fake/<name>/rules.json`, no code needed.
* Get `FakeLlmDir` from `ExtensionLlmTest#getFakeLlm()` (the test add-on must depend on `llmTest`) and
  call `addRuleSet(name, supplier)`, and `removeRuleSet(name)` when unloaded. A rule set added this
  way takes precedence over a file with the same name.

Rule set names can only contain letters, digits, `_` and `-`. The `example` rule set is an example.

## Integration tests

`src/main/zapHomeFiles/integration-tests/llm/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/llm/plans` in the ZAP home, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/llm/plans/fake-llm.yaml
