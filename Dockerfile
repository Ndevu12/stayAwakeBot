# syntax=docker/dockerfile:1
#
# StayAwakeBot container image. Goal of this channel (P3): remove the Python 3.14 install
# barrier from the host — you need only Docker, not a 3.14 toolchain — while keeping the
# project's supply-chain posture (digest-pinned base, non-root, hermetic build).
#
# Base is pinned by DIGEST, never a mutable tag (same doctrine as the SHA-pinned Actions).
# Refresh the digest deliberately:  docker buildx imagetools inspect python:3.14-slim
ARG PYTHON_IMAGE=python:3.14-slim@sha256:63a4c7f612a00f92042cbdcc7cdc6a306f38485af0a200b9c89de7d9b1607d15

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
COPY --chown=builder:builder pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY --chown=builder:builder src ./src

RUN pip install --no-cache-dir --user build \
 && python -m build --wheel --outdir /dist

# ───────────────────────── runtime: slim, non-root, package only ────────────────────────
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.source="https://github.com/Ndevu12/stayAwakeBot" \
      org.opencontainers.image.description="StayAwakeBot — supply-chain worm hunter + uptime sentinel" \
      org.opencontainers.image.licenses="MIT"

# The scanner only ever reads code and never needs root; run as an unprivileged user, and
# install the wheel into a user-owned virtualenv so pip runs as `sentinel`, never root. The
# root steps here are useradd / venv creation / chown only — pip itself runs unprivileged.
RUN useradd --create-home --uid 10001 sentinel \
 && python -m venv /opt/venv \
 && chown -R sentinel:sentinel /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY --from=builder --chown=sentinel:sentinel /dist/*.whl /tmp/

USER sentinel
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Default reports to a container-owned, writable dir. The repo is mounted at /repo, often
# read-only (`:ro`) or owned by the host user, so the scanner's default `reports/security`
# there isn't writable by `sentinel` (uid 10001). Writing inside the image avoids the crash;
# bind-mount this path (or pass --reports-dir to a dir you own) to keep the reports.
ENV STAYAWAKE_REPORTS_DIR=/home/sentinel/reports

WORKDIR /repo

# Mount the repository to scan at /repo (read-only is fine for scanning), e.g.:
#   docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot \
#     stayawake-security-scan --local-only --fail-on-findings
# The package ships several console scripts, so there is no single ENTRYPOINT — name the
# command you want. A bare `docker run` prints the security scanner's help.
CMD ["stayawake-security-scan", "--help"]
