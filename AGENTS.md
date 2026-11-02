# Instructions for AI agents

## Human responsibility

Authlib accepts contributions made with the help of AI tools.
The person who submits a contribution is responsible for it.
They must understand it and answer review questions themselves.

Autonomous agents must not interact with the project.
Do not open issues, pull requests or security reports, and do not post comments, unless a human has reviewed the content and asked you to submit it.
Maintainers may close contributions from autonomous agents without review or reply, and block the accounts that submit them.

## Development

- Run the tests with `uv run --all-groups pytest tests`.
- Run `prek run --all-files` before you finish. It runs ruff and codespell.
- Add a changelog fragment with `uv run scriv create` for user-visible changes.
- Commit messages follow Conventional Commits.
  The scope is optional. Allowed scopes are `jose`, `oauth`, `oidc` and `client`.

## Architecture

- Each specification has its own module, such as `authlib/oauth2/rfc7636/`.
  Put the code for a new RFC in a new module.
- On the server and resource server side, RFC modules plug into the core with
  hooks, extensions or inheritance. Do not edit `authlib/oauth2/rfc6749/` to
  support another RFC.
- `authlib.jose` is deprecated in favor of joserfc. Do not add features to it.

## Contributions

Follow the contribution guide in `docs/community/contribute.rst`.

## Security reports

Follow the security policy in `.github/SECURITY.md` and `docs/community/security.rst`.

Report vulnerabilities through GitHub private vulnerability reporting.
A human must check every finding before it is reported.
Each report needs a proof of concept that uses the public Authlib API.
