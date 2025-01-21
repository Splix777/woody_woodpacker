FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    nasm \
    gcc \
    clang \
    lldb \
    gdb \
    make \
    bsdmainutils \
    python3 \
    python3-pip \
    libc6-dev \
    binutils \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY . .

CMD ["/bin/bash"]
