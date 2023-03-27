ARG swift_repo=swift
ARG swift_version=5.7
ARG ubuntu_version=jammy
ARG base=$swift_repo:$swift_version-$ubuntu_version
FROM $base

# needed to do again after FROM due to docker limitation
ARG swift_version
ARG ubuntu_version

# Install OS updates and set as UTF-8
RUN apt-get update -q \
    && apt-get -q dist-upgrade -y \
    && apt-get -q install -y locales locales-all python3 \
    && rm -rf /var/lib/apt/lists/*

ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8
