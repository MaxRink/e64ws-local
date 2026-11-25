FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bison flex gettext texinfo unzip bc rsync cpio \
    python3 perl libncurses5-dev libncursesw5-dev file wget curl \
    ca-certificates git patch gawk sed libssl-dev bzip2 xz-utils \
    binutils-arm-linux-gnueabihf qemu-user-static kmod \
    vim-tiny less && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
