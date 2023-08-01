FROM alpine
ARG profile=release
RUN apk add --no-cache cargo
COPY Cargo.lock Cargo.toml /src/
WORKDIR /src/
# fetch and compile dependencies using dummy main file
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --profile=${profile}
COPY ./ /src/
# touch main file so it actually gets compiled with correct main file
RUN touch src/main.rs && cargo build --locked --frozen --profile=${profile}
CMD /src/target/release/pqc_pon