# building is a seperate step. This causes the source code
# to not be leaked into the resulting container
# Use ubuntu 20.04 (same as office-supplies) to save some storage on the vulnbox
FROM ubuntu:20.04 as build
RUN apt update && apt install -y build-essential libsqlite3-dev
WORKDIR /build
COPY *.c *.h ./
COPY Makefile ./
RUN make

# The actual running container
FROM ubuntu:20.04
RUN apt-get -y update && apt-get install -y socat binutils libsqlite3-0

COPY --from=build /build/tic-tac-toe /

ENTRYPOINT socat -6 tcp-listen:1337,fork,reuseaddr EXEC:/tic-tac-toe
EXPOSE 1337/tcp
