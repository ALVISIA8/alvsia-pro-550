# Free API audit workflow setup

This workflow is an opt-in, manual source-audit helper. It does **not** edit or commit application source code and does not run a release build.

## Before running

The workflow sends up to 65,000 characters of eligible repository source to the third-party API configured by you. Do not run it unless you are comfortable sharing that source with that provider. It excludes common build-output folders and keystore/secret-named files, but source code can still contain sensitive material; review the repository first.

## Configure GitHub

In **Settings → Secrets and variables → Actions**, add:

- Repository secret `FREE_CHATGPT_API_KEY`: your API key. Never put it in a workflow file, commit, issue, or chat.
- Repository variable `FREE_CHATGPT_API_BASE_URL`: the provider's documented HTTPS base URL ending in `/v1`.
- Repository variable `FREE_CHATGPT_API_MODEL`: an exact model ID supported by your key.

The endpoint must support OpenAI-compatible `POST /chat/completions` requests and return `choices[0].message.content`. Verify these details in the exact provider's documentation before running. Do not assume every fork of a similarly named project uses the same endpoint.

## Run

Open **Actions → Free API Source Audit → Run workflow**. Select a scope and run it manually. Download the `alvisia-free-api-audit` artifact to read the report.

## Safe workflow

1. Treat the generated report as suggestions, not verified facts.
2. Confirm each claimed issue against the cited source.
3. Implement small changes on a separate branch.
4. Run project tests and build checks before merging.
5. Never disable authentication, OTP, authorization, TLS pinning, or runtime protection merely to make a build pass.

The report is not a substitute for Android device testing. The workflow does not claim that any of the app's tools are fixed until they are individually tested.
