FROM ubuntu:22.04

# System updates and core tools
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y \
       python3 ipython3 python3-pip git gdb gdbserver qemu-user qemu-user-static binfmt-support gdb-multiarch tmux wget nano \
        libc6-i386-cross \
        libc6-armel-cross \
        libc6-arm64-cross \
        libc6-riscv64-cross \
        libc6-mips64-cross \
        binutils-multiarch \
    && python3 -m pip install --upgrade pip timeout_decorator git+https://github.com/Angelo942/libdebug.git sortedcontainers pyserial pyelftools zstandard urllib3 unix-ar unicorn six pysocks pygments pycparser psutil plumbum packaging MarkupSafe intervaltree idna charset-normalizer certifi capstone bcrypt rpyc ropgadget requests python-dateutil mako colored_traceback cffi pynacl cryptography paramiko pwntools

# Create non-root home dir
RUN mkdir -p /home/root \
    && sed -i 's|^root:[^:]*:/root|root:x:/home/root|' /etc/passwd
WORKDIR /home/root

RUN mkdir /etc/qemu-binfmt && ln -s /usr/i386-linux-gnu/  /etc/qemu-binfmt/i386 && ln -s /usr/arm-linux-gnueabi/   /etc/qemu-binfmt/armel && ln -s /usr/aarch64-linux-gnu/   /etc/qemu-binfmt/aarch64 && ln -s /usr/riscv64-linux-gnu/   /etc/qemu-binfmt/riscv64 && ln -s /usr/mips64-linux-gnuabi64/ /etc/qemu-binfmt/mips64

# Install pwndbg from local clone (mounted via compose)
RUN git clone https://github.com/pwndbg/pwndbg.git /home/root/pwndbg \
    && cd /home/root/pwndbg \
    && ./setup.sh

# Create entrypoint script for installing gdb_plus at runtime and launching tmux
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default working directory for tests
WORKDIR /home/root/gdb_plus/tests

RUN printf 'set history save off\nset pagination off\n' > /root/.gdbinit

RUN echo 'set -g mouse on' > /root/.tmux.conf

RUN apt-get install -y software-properties-common
RUN apt-get install -y binutils-aarch64-linux-gnu binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf binutils-mips64el-linux-gnuabi64 binutils-mipsel-linux-gnu binutils-mips-linux-gnu binutils-x86-64-linux-gnu binutils-riscv64-linux-gnu

RUN apt install libclang-dev
RUN pip3 install clang==14.0.0

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]