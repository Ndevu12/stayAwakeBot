---
description: saw doctor — self-check the installation, the active GitHub credential and what it is allowed to do.
---

# `saw doctor`

```text
saw doctor [--json] [-q] [--no-stream]
```

Checks that `saw` runs this copy, which GitHub credential it uses and whether that credential can
open fix and guard pull requests, whether a saw GitHub App is set up, and that saw's CI health tools
are installed. When the credential is missing or cannot open pull requests, it names the command to
run. `saw auth status` shows everything the credential can do. `-q` prints only problems.
