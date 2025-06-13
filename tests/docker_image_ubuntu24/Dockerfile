FROM ubuntu:24.04

# System updates and core tools
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y \
       python3 ipython3 python3-pip python3-venv git gdb gdb-multiarch gdbserver qemu-user binfmt-support tmux wget nano \
       libc6-i386-cross \
       libc6-armel-cross \
       libc6-arm64-cross \
       libc6-riscv64-cross \
       libc6-mips64-cross \
       binutils-multiarch \
    && python3 -m venv /opt/venv

# Activate virtual environment and install Python packages
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install --upgrade pip timeout_decorator \
       git+https://github.com/Angelo942/libdebug.git sortedcontainers pyserial pyelftools \
       zstandard urllib3 unix-ar unicorn six pysocks pygments pycparser psutil plumbum packaging \
       MarkupSafe intervaltree idna charset-normalizer certifi capstone bcrypt rpyc ropgadget \
       requests python-dateutil mako colored_traceback cffi pynacl cryptography paramiko pwntools

# Create non-root home dir
RUN mkdir -p /home/root \
    && sed -i 's|^root:[^:]*:/root|root:x:/home/root|' /etc/passwd
WORKDIR /home/root

# Install pwndbg from local clone (mounted via compose)
RUN git clone https://github.com/pwndbg/pwndbg.git /home/root/pwndbg \
    && cd /home/root/pwndbg \
    && ./setup.sh

# Copy and setup entrypoint for installing gdb_plus and launching tmux
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default working directory for tests
WORKDIR /home/root/gdb_plus/tests

# Disable gdb history/pagination and enable tmux mouse
RUN printf 'set history save off\nset pagination off\n' > /root/.gdbinit \
    && echo 'set -g mouse on' > /root/.tmux.conf

# Install additional cross binutils and supporting tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    software-properties-common \
    binutils-aarch64-linux-gnu \
    binutils-arm-linux-gnueabi \
    binutils-arm-linux-gnueabihf \
    binutils-mips64el-linux-gnuabi64 \
    binutils-mipsel-linux-gnu \
    binutils-mips-linux-gnu \
    binutils-x86-64-linux-gnu \
    binutils-riscv64-linux-gnu

RUN ln -s /usr/i386-linux-gnu/ /srv/i386-rootfs && \
    ln -s /usr/arm-linux-gnueabi/ /srv/armel-rootfs && \
    ln -s /usr/aarch64-linux-gnu/ /srv/aarch64-rootfs && \
    ln -s /usr/riscv64-linux-gnu/ /srv/riscv64-rootfs && \
    ln -s /usr/mips64-linux-gnuabi64/ /srv/mips64-rootfs
    
RUN for bin in qemu-i386 qemu-arm qemu-aarch64 qemu-riscv64 qemu-mips64; do \
    [ -e /usr/bin/$bin ] || continue; \
    mv /usr/bin/$bin /usr/bin/$bin.real; \
    arch=${bin#qemu-}; \
    printf '#!/bin/sh\nexport QEMU_LD_PREFIX=/srv/%s-rootfs\nexec /usr/bin/%s.real "$@"\n' \
      "$arch" "$bin" > /usr/bin/$bin && \
    chmod +x /usr/bin/$bin; \
  done

RUN echo "python" >> /root/.gdbinit \
  && echo "import sys; sys.path.insert(0, '/opt/venv/lib/python3.12/site-packages')" >> /root/.gdbinit \
  && echo "end" >> /root/.gdbinit

RUN apt install libclang-dev
RUN pip3 install clang==18.1.8

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
