# Verity attestor — the witness that performs the TLS check and signs zkTLS proofs.
# Built from reclaimprotocol/attestor-core pinned to a known-good commit plus one
# patch (min-client-version.patch), run under our own signing key. Deploys on Railway.
FROM node:24-bookworm

# Native build deps for re2 (runtime regex engine) + git to fetch the pinned source.
RUN apt-get update \
  && apt-get install -y --no-install-recommends git python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pin the attestor implementation. Bump deliberately; do not float.
# dd43dc8 carries the zk-symmetric-crypto 5.1.7 proof-soundness fix.
ARG ATTESTOR_COMMIT=dd43dc882b88dcfe75d27a1c1a991315574823ab
RUN git clone https://github.com/reclaimprotocol/attestor-core.git . \
  && git checkout ${ATTESTOR_COMMIT}

COPY min-client-version.patch /tmp/
RUN git apply /tmp/min-client-version.patch

# Install without the package's own build step; compile re2. The stwo engine's
# wasm ships inside the package, so download:zk-files (332 MB) is skipped.
RUN npm install --ignore-scripts \
  && (npm rebuild re2 || true)

ENV NODE_ENV=production
# PRIVATE_KEY (and optional AUTHENTICATION_PUBLIC_KEY) come from Railway service variables.
EXPOSE 8001
CMD ["node", "--experimental-strip-types", "src/scripts/start-server.ts"]
