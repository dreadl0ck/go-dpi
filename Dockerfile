FROM golang:1.25.1
RUN echo "deb http://packages.wand.net.nz trusty main" | tee -a /etc/apt/sources.list
RUN curl https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg
RUN apt update
RUN apt -y install autoconf automake libtool git libpcap-dev libtrace4 libtrace4-dev libprotoident libprotoident-dev liblinear3 liblinear-dev pkg-config
RUN git clone --depth 1 --branch 4.14 https://github.com/ntop/nDPI/ /tmp/nDPI
RUN cd /tmp/nDPI && ./autogen.sh && ./configure && make && make install && cd -

RUN mkdir -p $GOPATH/src/github.com/dreadl0ck/go-dpi
WORKDIR $GOPATH/src/github.com/dreadl0ck/go-dpi
ADD . .
RUN go build ./... && \
    go test ./... && \
    go test -bench=. && \
    go install ./godpi_example

ENTRYPOINT ["godpi_example"]
