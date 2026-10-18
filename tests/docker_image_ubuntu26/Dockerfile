FROM ubuntu:26.04

# System updates and core tools
# 26.04 no longer ships libc6-mips64-cross: mips64 only runs the freestanding fixtures (clang + lld)
# cmake: pwntools pins unicorn 2.1.2, which has no python 3.14 wheel and is built from source
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y \
        python3 ipython3 python3-pip python3-venv git gdb gdb-multiarch gdbserver qemu-user binfmt-support tmux wget nano libclang-dev build-essential gcc-multilib \
        clang lld cmake pkg-config file \
        libc6-i386-cross \
        libc6-armel-cross \
        libc6-arm64-cross \
        libc6-riscv64-cross \
        binutils-multiarch \
        software-properties-common \
        binutils-aarch64-linux-gnu \
        binutils-arm-linux-gnueabi \
        binutils-arm-linux-gnueabihf \
        binutils-mips64-linux-gnuabi64 \
        binutils-mips64el-linux-gnuabi64 \
        binutils-mipsel-linux-gnu \
        binutils-mips-linux-gnu \
        binutils-x86-64-linux-gnu \
        binutils-riscv64-linux-gnu \
    && python3 -m venv /opt/venv

# Activate virtual environment and install Python packages
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install --upgrade pip timeout_decorator pytest pytest-xdist pyflakes \
       git+https://github.com/Angelo942/libdebug.git sortedcontainers pyserial pyelftools \
       zstandard urllib3 unix-ar unicorn six pysocks pygments pycparser psutil plumbum packaging \
       MarkupSafe intervaltree idna charset-normalizer certifi capstone bcrypt rpyc ropgadget \
       requests python-dateutil mako colored_traceback cffi pynacl cryptography paramiko pwntools clang==21.1.7

# Create non-root home dir
RUN mkdir -p /home/root \
    && sed -i 's|^root:[^:]*:/root|root:x:/home/root|' /etc/passwd
WORKDIR /home/root

# Install pwndbg from local clone (mounted via compose)
RUN git clone https://github.com/pwndbg/pwndbg.git /home/root/pwndbg \
    && cd /home/root/pwndbg \
    && ./setup.sh

# GEF for --gdb-flavor=gef (not loaded by default)
RUN wget -q -O /root/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py

# Copy and setup entrypoint for installing gdb_plus and launching tmux
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default working directory for tests
WORKDIR /home/root/gdb_plus/tests

# Disable gdb history/pagination and enable tmux mouse
RUN printf 'set history save off\nset pagination off\n' > /root/.gdbinit \
    && echo 'set -g mouse on' > /root/.tmux.conf

# qemu-<arch> looks for the guest libraries in its default QEMU_LD_PREFIX (/usr/gnemul/qemu-<arch>, also what
# pwntools passes with -L). Link it to the cross sysroots instead of wrapping /usr/bin/qemu-<arch> in a shell
# script: the tests open the emulator as an ELF (test_qemu_gdbserver)
RUN mkdir -p /usr/gnemul \
    && ln -s /usr/i386-linux-gnu /usr/gnemul/qemu-i386 \
    && ln -s /usr/arm-linux-gnueabi /usr/gnemul/qemu-arm \
    && ln -s /usr/aarch64-linux-gnu /usr/gnemul/qemu-aarch64 \
    && ln -s /usr/riscv64-linux-gnu /usr/gnemul/qemu-riscv64

# gdb's python needs rpyc (pwntools' API bridge) from the venv
RUN echo "python" >> /root/.gdbinit \
  && echo "import sys; sys.path.insert(0, '$(python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')')" >> /root/.gdbinit \
  && echo "end" >> /root/.gdbinit

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
