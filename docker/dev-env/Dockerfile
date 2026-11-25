# Development environment for the E64 WS research repository.
#
# Build:  docker build -t e64-dev-env docker/dev-env
# Run:    docker run --rm -it -v "$PWD:/work" -w /work e64-dev-env
#
# The vendor firmware is not included; fetch it with ./fetch_firmware.sh
# (shipped in the repository bundle) or the URL in docs/REPRODUCTION.md.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    NODE_PATH=/usr/lib/node_modules

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-venv \
        python3-pip \
        nodejs \
        npm \
        qemu-system-arm \
        e2fsprogs \
        mtools \
        cpio \
        libarchive-tools \
        binutils \
        file \
        git \
        jq \
        less \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# REA MCP server (reverse-engineering tooling for agents). Optional at runtime,
# but small enough to include so `rea doctor` works inside the container.
RUN npm install -g --no-fund --no-audit rea-agents@6.8.0 || true

# Python dependencies used by the simulator and clients.
COPY tools/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

WORKDIR /work

# The repository is mounted at /work; nothing is baked in so the image stays
# usable for any revision of the research tree.
CMD ["/bin/bash"]
