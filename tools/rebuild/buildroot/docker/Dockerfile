FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
# Ubuntu 26.04 dropped the packages this image used to name directly:
#   libncurses5-dev / libncursesw5-dev -> libncurses-dev (it Provides both)
#   qemu-user-static                   -> qemu-user-binfmt (static qemu-* plus
#                                         the binfmt.d registrations)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bison flex gettext texinfo unzip bc rsync cpio \
    python3 perl libncurses-dev file wget curl \
    ca-certificates git patch gawk sed libssl-dev bzip2 xz-utils \
    binutils-arm-linux-gnueabihf qemu-user-binfmt kmod \
    vim-tiny less && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
