ARG ALPINE_TAG=3.8
FROM base/archlinux

RUN curl \
      -s "https://www.archlinux.org/mirrorlist/?country=DE&country=US&protocol=https&use_mirror_status=on" \
      | sed -e 's/^#Server/Server/' -e '/^#/d' > /etc/pacman.d/mirrorlist
RUN pacman -Syyuu --noconfirm
RUN pacman --noconfirm -S cmake clang make gcc python wget

RUN mkdir /afl
COPY bin /afl/bin
COPY src /afl/src
COPY include /afl/include
COPY CMakeLists.txt /afl/CMakeLists.txt 
COPY .clang-format /afl/.clang-format

WORKDIR /afl
RUN bin/ci.sh
