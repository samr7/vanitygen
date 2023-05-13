FROM ubuntu:18.04

# Pull in latest sources and upgrade packages
RUN apt-get update && apt-get -y upgrade


RUN apt-get -y install build-essential

RUN apt-get -y install libssl-dev



RUN apt-get install -y libssl1.0-dev
# RUN apt-get install libssl-dev -y

RUN apt-get install -y libpcre-ocaml libpcre++-dev
