# Merge-to-Pay agent. Build context = REPO ROOT (needs packages/sdk); Railway reads /railway.json.
# Native barretenberg 0.84.0 needs glibc >= 2.38: trixie ships 2.41.
FROM node:24-trixie-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# bb v0.84.0 amd64-linux from the official aztec-packages release, pinned by sha256.
ARG BB_URL=https://github.com/AztecProtocol/aztec-packages/releases/download/v0.84.0/barretenberg-amd64-linux.tar.gz
ARG BB_SHA256=770b17b0c383923bd0ad5268c0440d6d472971e1e39a77f3a57523d299435c6e
RUN curl -fsSL -o /tmp/bb.tar.gz "$BB_URL" \
  && echo "$BB_SHA256  /tmp/bb.tar.gz" | sha256sum -c - \
  && mkdir -p /opt/bb && tar -xzf /tmp/bb.tar.gz -C /opt/bb && rm /tmp/bb.tar.gz \
  && /opt/bb/bb --version

WORKDIR /app
COPY package.json package-lock.json ./
COPY packages packages
COPY apps/merge-to-pay apps/merge-to-pay
# Only this workspace (+ the sdk it links). re2/koffi fall back without their build scripts.
RUN npm ci --workspace apps/merge-to-pay --omit=dev --ignore-scripts

ENV NODE_ENV=production BB_BIN=/opt/bb/bb BB_CRS=/app/crs DATA_DIR=/data PORT=8080
WORKDIR /app/apps/merge-to-pay
# Bake the CRS: one real prove of a fixture (same circuit, --zk, keccak) pulls exactly the points this
# circuit needs into /app/crs, and proves the image can prove. No CRS network calls at runtime.
RUN node --input-type=module -e "import { proveClaim } from './src/prover.mjs'; import { readFileSync } from 'node:fs'; \
  const r = await proveClaim(JSON.parse(readFileSync('test/fixtures/nodejs-node-49999.proof.json', 'utf8'))); \
  console.log('CRS baked; proof', (r.proofHex.length - 2) / 2, 'B in', Math.round(r.ms.prove), 'ms')" > /tmp/bake.log 2>&1 \
  || (cat /tmp/bake.log; exit 1); cat /tmp/bake.log; ls -la /app/crs

EXPOSE 8080
CMD ["node", "src/server.mjs"]
