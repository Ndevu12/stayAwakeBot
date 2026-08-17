---
description: saw intro — a short tour of what saw is, its verbs, and why it is safe to run.
---

# `saw intro`

```text
saw intro          # or: saw welcome  ·  or just: saw
```

Bare `saw` prints the short welcome; `saw intro` prints the fuller tour. Both run no scan and touch
nothing. Colour degrades to the terminal's capability and is dropped entirely when output is piped or
redirected, when `NO_COLOR` is set, under CI, or on a `TERM=dumb` terminal; `CLICOLOR_FORCE=1` forces
it on.
