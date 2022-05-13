FROM ubuntu:18.04 as base

# Install pip3 to get access to apt-select
RUN apt-get -y update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        python3-pip

# Install apt-select so rest of installation is fast
RUN pip3 install apt-select && \
    apt-select -C us -m one-day-behind && \
    mv /etc/apt/sources.list /etc/apt/sources.list.backup && \
    mv sources.list /etc/apt/

# install required build/test tools
RUN apt-get -y update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install \
        build-essential \
        cmake \
        curl \
        default-jdk \
        gcc-arm-linux-gnueabi \
        g++-arm-linux-gnueabi \
        gcc-arm-linux-gnueabihf \
        g++-arm-linux-gnueabihf \
        git \
        libc6-dev-armel-cross \
        libcairo2 \
        python3.8 \
        python3.8-dev \
        python3.8-venv \
        python3-venv \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        unzip \
        wget \
        zip \
    && apt-get clean \
    && python3.8 -m pip install --upgrade \
        pip \
        setuptools

COPY . /ghidra_retypd
WORKDIR /ghidra_retypd

ENV PATH="/ghidra_retypd/util/:/ghidra_retypd/third-party/gradle/bin:${PATH}"
# get ghidra
RUN .ci/get_ghidra.sh

# Ghidra environment variables
ENV GHIDRA_HOME=/ghidra_retypd/third-party/ghidra/
ENV GHIDRA_INSTALL_DIR=/ghidra_retypd/third-party/ghidra/
ENV CLASSPATH=.:$GHIDRA_HOME/support/ghidra.jar

# Install the extension
RUN make && make install

FROM base as interactive

RUN python3.8 -m venv venv
RUN . ./venv/bin/activate

# Install retypd into the virtual environment
RUN git clone https://github.com/GrammaTech/retypd.git /retypd/
WORKDIR /retypd
RUN python3.8 -m pip install .

# Install ghidra_retypd into the virutal environment
WORKDIR /ghidra_retypd
RUN python3.8 -m pip install .
