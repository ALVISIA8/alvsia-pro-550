# Free API audit workflow setup

This workflow is an opt-in, manual source-audit helper. It does **not** edit or commit application source code and does not run a release build.

## Important: rotate exposed credentials first

An API key was pasted into a chat. Treat it as exposed: revoke/rotate it at the provider, then store only the replacement in GitHub Actions Secrets. Do not reuse the exposed key. The OAuth callback URL/code was also shared; do not repost it. If the GitHub authorization was not intended or you are unsure, review and revoke the app authorization in GitHub Settings.

## Before running

The workflow sends up to 65,000 characters of eligible repository source to the third-party API configured by you. Do not run it unless you are comfortable sharing that source with that provider. It excludes common build-output folders and some secret-named files, but source code can still contain credentials or proprietary logic; review the repository and provider terms first.

## Configure GitHub

In **Settings → Secrets and variables → Actions**, add:

- Repository secret `FREE_CHATGPT_API_KEY`: the **newly rotated** API key. Never put it in a workflow file, commit, issue, or chat.
- Repository variable `FREE_CHATGPT_API_BASE_URL`: `https://free.v36.cm` or `https://free.v36.cm/v1`. The workflow normalizes either form to the v1 API path.
- Repository variable `FREE_CHATGPT_API_MODEL`: optional. If omitted, the workflow queries `GET /v1/models` and selects a returned model ID, preferring `gpt-4o-mini` if listed.

The endpoint must support OpenAI-compatible `GET /v1/models` and `POST /v1/chat/completions`, returning `choices[0].message.content`. Provider model availability, quotas and behavior may change.

## Run

Open **Actions → Free API Source Audit → Run workflow**. Select a scope and run it manually. Download the `alvisia-free-api-audit` artifact to read the report.

## Safe workflow

1. Treat the generated report as suggestions, not verified facts.
2. Confirm each claimed issue against the cited source.
3. Implement small changes on a separate branch.
4. Run project tests and build checks before merging.
5. Never disable authentication, OTP, authorization, TLS pinning, or runtime protection merely to make a build pass.

The report is not a substitute for Android device testing. The workflow does not claim that any of the app's tools are fixed until they are individually tested.
