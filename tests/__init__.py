from tests.support import isolation as _isolation

_isolation.install()

from stayawake.lib.git import allowlist as _git_allowlist  # noqa: E402

_git_allowlist.RAISE_ON_REFUSAL = True
