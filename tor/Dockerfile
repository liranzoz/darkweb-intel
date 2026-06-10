FROM alpine:latest
RUN apk add --no-cache tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
