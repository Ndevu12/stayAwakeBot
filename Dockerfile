# syntax=docker/dockerfile:1
#
# StayAwakeBot container image. Goal of this channel (P3): remove the Python 3.14 install
# barrier from the host — you need only Docker, not a 3.14 toolchain — while keeping the
# project's supply-chain posture (digest-pinned base, non-root, hermetic build).
#
# Base is pinned by DIGEST, never a mutable tag (same doctrine as the SHA-pinned Actions).
# Refresh the digest deliberately:  docker buildx imagetools inspect python:3.14-slim
# Refresh it in every release PR: the pin is fixed, the advisory feed is not. Multi-arch index digest.
ARG PYTHON_IMAGE=python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

# ───────────────────────── builder: build the wheel from source ─────────────────────────
FROM ${PYTHON_IMAGE} AS builder

# Build as an unprivileged user so pip never runs as root (no root-owned caches, none of the
# "running pip as the root user" hazard) even though this stage is discarded. The only root
# steps are useradd + mkdir/chown of the work dirs — never pip.
RUN useradd --create-home --uid 10001 builder \
 && mkdir /build /dist \
 && chown builder:builder /build /dist
USER builder
WORKDIR /build
# `pip install --user` keeps build's deps in the user site; put its console scripts on PATH.
ENV PATH=/home/builder/.local/bin:$PATH

# hatch-vcs derives the version from git history, which is deliberately NOT in the build
# context (.dockerignore). Feed the version in explicitly so the build is hermetic and needs
# no .git. The release workflow passes the tag version; local builds get a dev placeholder.
# NOTE: the generic PRETEND var is used, not the `_FOR_STAYAWAKEBOT` named one — hatch-vcs's
# backend (vcs-versioning) doesn't receive the dist name, so the named variant is ignored
# (verified). Safe here because this stage builds exactly one package.
ARG VERSION=0.0.0.dev0+docker
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${VERSION}

# Copy only what the wheel build needs (matches the Dockerfile's whitelist .dockerignore).
COPY --chown=builder:builder pyproject.toml README.md LICENSE COMMERCIAL-LICENSE.md CHANGELOG.md ./
COPY --chown=builder:builder src ./src

RUN pip install --no-cache-dir --user build \
 && python -m build --wheel --outdir /dist

# ───────────────────────── runtime: slim, non-root, package only ────────────────────────
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.source="https://github.com/Ndevu12/stayAwakeBot" \
      org.opencontainers.image.description="StayAwakeBot — supply-chain worm hunter + uptime sentinel" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# The scanner only ever reads code and never needs root; run as an unprivileged user, and install
# the wheel into a user-owned virtualenv so pip runs as `sentinel`, never root. pip itself is then
# dropped — nothing installs at run time — with `test -d` first so a layout change fails loudly.
RUN set -eux; \
    useradd --create-home --uid 10001 sentinel; \
    python -m venv /opt/venv; \
    chown -R sentinel:sentinel /opt/venv; \
    base_site="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
    test -d "$base_site/pip"; \
    rm -rf "$base_site/pip" "$base_site"/pip-*.dist-info \
           "$(python -c 'import ensurepip, os; print(os.path.dirname(ensurepip.__file__))')" \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.*
ENV PATH=/opt/venv/bin:$PATH

# Dependencies come from the lock, verified by hash, NOT resolved fresh at build time. Without
# this the image installs whatever PyPI serves that minute: two builds of one commit differ, and a
# poisoned release of any dependency enters the image unnoticed — the exact attack this tool exists
# to detect. --require-hashes makes pip refuse anything whose SHA-256 does not match the lock.
COPY --chown=sentinel:sentinel requirements.lock /tmp/
COPY --from=builder --chown=sentinel:sentinel /dist/*.whl /tmp/

USER sentinel
# --no-deps on the wheel is load-bearing: dependencies are the lock's job, and the wheel must not be
# able to pull in anything unpinned alongside it.
RUN set -eux; \
    pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock; \
    pip install --no-cache-dir --no-deps /tmp/*.whl; \
    rm -f /tmp/*.whl /tmp/requirements.lock; \
    venv_site="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
    test -d "$venv_site/pip"; \
    rm -rf "$venv_site/pip" "$venv_site"/pip-*.dist-info \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.*

# Build-time proof the CLI still resolves and runs with pip gone.
RUN saw --version

WORKDIR /repo

# A bare `saw scan` persists nothing; reports are written only when you ask for them with
# `-d/--reports-dir` (or via this var, which supplies the default for that flag). This points
# at a container-internal path the runtime user can always write — a host bind-mount
# (e.g. -v "$PWD:/repo:ro") is owned by the host uid and isn't writable by `sentinel`, so the
# verdict (exit code) shouldn't depend on persisting a report there. Report writing also
# degrades gracefully if the chosen dir turns out unwritable.
ENV STAYAWAKE_REPORTS_DIR=/tmp/stayawake

# Mount the repository to scan at /repo (read-only is fine for scanning), e.g.:
#   docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot \
#     saw scan --local
# `saw scan` exits non-zero when infected (the exit code is the verdict), so it gates CI
# directly. To keep a report on the host, mount a writable dir and run as your own uid so the
# bind-mount is writable:
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" \
#     ghcr.io/ndevu12/stayawakebot saw scan --local --reports-dir /repo/reports
# The package ships the `saw` CLI plus the stayawake-health-* console scripts, so there is no
# single ENTRYPOINT — name the command you want. A bare `docker run` prints the saw CLI help.
CMD ["saw", "--help"]
