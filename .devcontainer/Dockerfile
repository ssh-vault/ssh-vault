FROM rust
RUN apt update && apt install -y --no-install-recommends -q build-essential ca-certificates curl git gnupg2 jq netcat openssl sudo vim zsh
RUN rustup component add rustfmt clippy
RUN cargo install cargo-expand cargo-edit
WORKDIR /home/
