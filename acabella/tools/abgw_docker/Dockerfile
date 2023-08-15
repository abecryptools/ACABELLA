# syntax=docker/dockerfile:1
FROM ubuntu:16.04 

RUN apt update -y
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get install -y tzdata
RUN dpkg-reconfigure --frontend noninteractive tzdata
RUN apt-get --assume-yes install software-properties-common
RUN echo "export GGM_PATH=/root/ggm-symbolic-solver" >> /etc/bash.bashrc

RUN apt install git vim build-essential sudo python3-dev wget flex bison python3-pip libssl-dev libgmp10 libgmp-dev git openssl -y
RUN apt-get install -y curl ocaml ocaml-native-compilers opam libtool libtool-bin libgmp-dev libffi-dev m4 libz-dev libssl-dev camlp4-extra

WORKDIR /root
RUN git clone https://github.com/miguel-ambrona/ggm-symbolic-solver
WORKDIR /root/ggm-symbolic-solver
RUN opam init --yes
RUN eval `opam config env`
RUN opam pin add symbolic-solver . -n --yes
RUN opam install symbolic-solver --deps-only --yes
RUN export GGM_PATH=/root/ggm-symbolic-solver/
RUN apt-add-repository -y ppa:aims/sagemath
RUN apt-get update -y
RUN apt-get --assume-yes install sagemath-upstream-binary

COPY ggm_setup.sh/ .
RUN chmod +x ggm_setup.sh
RUN ./ggm_setup.sh
RUN rm -rf examples/*
COPY solver_inputs/* examples/
COPY changes/* .

CMD ["/bin/bash"]








