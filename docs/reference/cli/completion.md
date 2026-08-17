---
description: saw completion — print a shell completion script for bash, zsh or fish.
---

# `saw completion`

```text
saw completion {bash,zsh,fish}
```

```bash
saw completion bash > /etc/bash_completion.d/saw     # or source it from ~/.bashrc
saw completion zsh  > "${fpath[1]}/_saw"
saw completion fish > ~/.config/fish/completions/saw.fish
```

The verb aliases a completed command line may use are listed under [command
aliases](index.md#command-aliases).
