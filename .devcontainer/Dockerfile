# Use an official Ubuntu image as a base
FROM ubuntu:latest

# Set non-interactive mode for package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    make \
    g++ \
    python3 \
    python3-pip \
    python3-venv \
    git \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Set Python3 as default
RUN ln -s /usr/bin/python3 /usr/bin/python

# Set working directory
WORKDIR /workspace

# Use root as the default user
USER root

# Default shell to zsh
SHELL ["/bin/zsh", "-c"]
