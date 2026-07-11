# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/mayhemheroes/base). The base provides debian 13 + clang/llvm + libFuzzer/afl++ + the
# identities + the build-contract ENV; this only adds open5gs's build deps and the per-commit build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t open5gs-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declare it WITHOUT a default so an unset arg lets the base ENV flow through; --build-arg overrides.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# open5gs builds with meson/ninja. The TWO fuzzers only LINK the protocol libs (core/proto/app/ipfw +
# nas/gtp), but the top-level `meson setup` CONFIGURES the whole project, so configure needs the full
# dependency set (gnutls/ssl/curl/microhttpd/nghttp2/mongoc+bson/sctp/idn/tins/talloc/yaml). meson then
# builds ONLY the two fuzzer targets (the SBI/NF daemons + mongodb code are never compiled or linked).
# Install the build deps as root, then drop back to the non-root 'mayhem' user.
#   - libidn11-dev provides legacy libidn.so that the freeDiameter subproject configure requires.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true; \
    apt-get update && apt-get install -yq --no-install-recommends \
      meson ninja-build flex bison build-essential cmake git pkg-config \
      libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn2-dev libidn11-dev \
      libmongoc-dev libbson-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev \
      libtins-dev libtalloc-dev libyaml-dev iproute2 autoconf libtool-bin zip \
      ca-certificates netbase \
    && rm -rf /var/lib/apt/lists/*
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run the functional parse oracle at build time (a failing oracle fails the image build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
