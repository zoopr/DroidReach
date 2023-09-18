FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y      \
    ninja-build             \
    openjdk-11-jdk-headless \
    python                  \
    python3-pip             \
    sudo                    \
    git                     \
    curl                    \
    wget                    \
    unzip                   \
    pkg-config

RUN pip install meson

ENV LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu/

# Rizin
RUN cd /opt                                               && \
    git clone https://github.com/rizinorg/rizin.git       && \
    cd /opt/rizin                                         && \
    git checkout 3752e24b989b45d30868624f4a973fef01466ad6 && \
    meson build                                           && \
    ninja -C build install

# Android SDK
RUN cd /opt && mkdir android-sdk && cd android-sdk                                          && \ 
    wget https://dl.google.com/android/repository/commandlinetools-linux-7583922_latest.zip && \
    unzip commandlinetools-linux-7583922_latest.zip                                         && \
    rm commandlinetools-linux-7583922_latest.zip                                            && \
    echo "y" | \
        ./cmdline-tools/bin/sdkmanager \
            --sdk_root=/opt/android-sdk "platforms;android-28" "platforms;android-29" "platforms;android-30"

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd --gid 1000 ubuntu \
   && useradd --uid 1000 --gid ubuntu --shell /bin/bash --create-home ubuntu
RUN echo "ubuntu ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu && \
    chmod 0440 /etc/sudoers.d/ubuntu

USER    ubuntu
WORKDIR /home/ubuntu

ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
ENV PYTHONUNBUFFERED=1
ENV PATH=$PATH:/home/ubuntu/.local/bin:/home/ubuntu/droidreach/bin

# Other dependencies
RUN pip install networkx==2.5.1 \
                yapsy           \
                angr==9.0.8021  \
                rzpipe          \
                pydot==1.4.2    \
                pyyaml          \
                psutil

# Angr fix (comment bugged debug print)
RUN sed -i '1619,1622 {s/^/#/}' /home/ubuntu/.local/lib/python3.8/site-packages/angr/analyses/cfg/cfg_emulated.py

# Androguard
RUN git clone https://github.com/androguard/androguard.git /tmp/androguard && \
    cd /tmp/androguard                                                     && \
    git checkout 8d091cbb309c0c50bf239f805cc1e0931b8dcddc                  && \
    pip install .                                                          && \
    rm -rf /tmp/androguard
    
USER root
WORKDIR /root/
# Ghidra
RUN cd /opt && wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.3_build/ghidra_9.2.3_PUBLIC_20210325.zip && unzip ghidra_9.2.3_PUBLIC_20210325.zip   &&  rm ghidra_9.2.3_PUBLIC_20210325.zip
# wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2_build/ghidra_9.2_PUBLIC_20201113.zip && \
# wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.1_build/ghidra_9.2.1_PUBLIC_20201215.zip && \
# wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.2_build/ghidra_9.2.2_PUBLIC_20201229.zip && \
# wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.4_build/ghidra_9.2.4_PUBLIC_20210427.zip && \
# wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip && \ 

ENV GHIDRA_HOME=/opt/ghidra_9.2.3_PUBLIC
