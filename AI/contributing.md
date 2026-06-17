# Contributing to wolfMQTT

## Contributor Agreement

External contributors must sign a contributor agreement before pull requests can be merged. When you open your first PR, a wolfSSL team member will ask you to email support@wolfssl.com referencing the PR. The agreement is tracked via wolfSSL's Zendesk ticketing system. Once signed, your PR will be approved for CI testing.

## Fork Workflow

Do not push branches to this repository. Fork to your personal GitHub account and open pull requests from your fork.

## Source Code Rules

CI enforces all of these on every PR. Violations block merge.

### Formatting

- **No trailing whitespace.** Files must end with a newline.
- **No hard tabs** in C, header, or YAML files. Makefiles are exempt.
- **ASCII only.** No non-ASCII bytes in source files. All code, comments, and string literals must be pure ASCII.
- **No CR characters** (`\r`). Use Unix line endings.

### C Style

- **C comments only.** Use `/* */`, not `//`, in all `.c` and `.h` files.
- Code follows the `.clang-format` at the repository root (LLVM base style, 4-space tab indentation, K&R inspired).

### AI Attribution

- **No AI attribution in commits.** CI rejects commits containing `Co-authored-by:` or `Signed-off-by:` trailers that reference:
  - `noreply@anthropic.com`
  - `noreply@openai.com`
  - `+Copilot@users.noreply.github.com`
  - Any `[bot]@users.noreply.github.com` address
- Commits authored by bot email addresses are also rejected.
- **Do not add these trailers.** Your PR will fail CI if they are present.

## PR Requirements

Every PR should include:

- **Description** of the scope of the fix or feature
- **Test description** — how the change was tested
- **Reference** to any related issue or Zendesk ticket (`Fixes zd#NNNN` for wolfSSL Zendesk tickets)

All CI checks must pass before merge.

## Testing Before Submitting

At minimum, run:

```bash
./autogen.sh && ./configure && make check
```

For broader coverage:

```bash
# All features
./configure --enable-all && make check

# Without external broker
WOLFMQTT_NO_EXTERNAL_BROKER_TESTS=1 ./configure --enable-all && make check

# Non-blocking
./configure --enable-nonblock && make check

# Multi-threading
./configure --enable-mt && make check

# MQTT-SN
./configure --enable-sn && make check
```

## Security Reports

Do not open GitHub issues for security vulnerabilities. Report them to support@wolfssl.com.
