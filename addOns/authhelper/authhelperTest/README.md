# Authhelper test add-on

Test apps and integration tests for the Authentication Helper add-on. The build configures it from its
location (`addOns/authhelper/authhelperTest`), see the Dev add-on help for how test add-ons work.
It depends on the LLM test add-on for the mock LLM.

## Multi-step auth

`http://localhost:9091/auth/multi-step-auth/` is a login with 3 steps: username and domain, department,
then password. It only succeeds if the domain `Project1` is selected, so LLM assisted authentication needs
the user hint `The domain pulldown needs to be set to Project1`.

### TOTP step

The app can also ask for a TOTP code as a 4th step, which is enabled with a POST to its `config` page, so the same
app can be tested in different modes. The current configuration is returned as JSON, a GET just returns it: only a
POST with `confirm=yes` changes it, so that neither spiders, nor browser extensions which re-request the URLs already
seen, nor crawlers submitting the configuration form with its default values can change it behind the back of a test.
The parameters, in the URL or the body, are:

* `totp` - `off` (the default, also resets the other parameters), `fixed` (the code must be the configured one) or
  `secret` (codes are generated from the shared secret, the current and adjacent periods are accepted).
* `layout` - `single` (the default, one field for the whole code) or `digits` (one field per digit, with neither `id`
  nor `name` so ZAP has to select them structurally).
* `code` - the fixed code, default `1234`.
* `secret` - the base32 shared secret, default `JBSWY3DPEHPK3PXP`.
* `digits` - the number of digits of generated codes, default 6.
* `confirm` - must be `yes`, otherwise the request is ignored.

For example, `POST http://localhost:9091/auth/multi-step-auth/config?totp=secret&layout=digits&confirm=yes`. The user
then needs the matching TOTP data: the `secret` (and `digits`) or, for a fixed code, the code as the secret with the
`FIXED` algorithm.

The configuration is kept until it is changed, a new ZAP session only clears the pending logins, so to test manually
follow the "configure the TOTP step" link at the bottom of the login page (`config.html`), choose the mode, change
"Confirm" to `yes` and apply (the JSON confirms it), then log in with `test@test.com` / `password123`, domain
`Project1` and any department. With `totp=fixed` the code is `1234`, with `totp=secret` use an authenticator app with
the secret (`oathtool --totp -b JBSWY3DPEHPK3PXP` also works). Each configuration change is logged at INFO level.

## Mock LLM rule set

`http://localhost:9091/llm/mock/authhelper/v1` replies with the actions needed to complete the multi-step
login, based on the URL in each turn. It also handles the TOTP step: the whole code in a single field, one digit per
field for 4 and 6 digit codes (based on the `cssPath` of the fields), and `MFA_REQUIRED` when the payload has no `totp`
credential. Add an `OpenAI Compatible` provider to the LLM add-on with that endpoint,
any model name and no API key. The rules are in `llm/mock/authhelper/rules.json` in `addOnData/dev/server`.

## Integration tests

`src/main/zapHomeFiles/integration-tests/authhelper/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/authhelper/plans` in the ZAP home. They need a browser, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/authhelper/plans/ai-auth-multi-step.yaml

Note that ZAP only adds `zapHomeFiles` which are missing from the ZAP home, so after changing a plan, a rule set or a
test page template either delete the old copy from the ZAP home or copy the new one over it. The mock LLM re-reads
its rules on every request, so the rules can be updated while ZAP is running.

* `ai-auth-multi-step.yaml` - LLM assisted authentication against the multi-step login, using the mock LLM.
* `ai-auth-wrong-domain.yaml` - the same, with a rule set that selects the wrong domain; authentication must fail.
* `ai-auth-totp-fixed.yaml` - with the TOTP step accepting a fixed code (`1234`) in a single field, the user has the
  code as the secret with the `FIXED` algorithm.
* `ai-auth-totp-fixed-digits.yaml` - the same, with one field per digit.
* `ai-auth-totp-secret.yaml` - with the TOTP step validating codes generated from a shared secret, in a single field.
* `ai-auth-totp-secret-digits.yaml` - the same, with one field per digit.
* `ai-auth-totp-missing.yaml` - with the TOTP step enabled but no TOTP data for the user; authentication must fail.

The plans configure the TOTP step of the test app at the start (and turn it off at the end), so they can be run in any
order. The TOTP plans also exercise the generated Zest script, since once LLM assisted authentication succeeds the
context is switched to Client Script Authentication and the script (with its `{{TOTP}}` or `{{TOTP_1}}`... variables)
is used to authenticate the user for the final request.

The `authhelper-wrong-domain` rule set (`/llm/mock/authhelper-wrong-domain/v1`) selects the wrong domain, and returns `FAILURE` when the login form is shown again.
