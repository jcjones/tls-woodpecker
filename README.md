# TLS-Woodpecker

Unlike the TLS Canary that evaluates many websites to determine if Firefox's
TLS stack is working well, *TLS-Woodpecker* pecks at a single website repeatedly
trying to catch intermittent breaks. It saves `.pcap` files from `tcpdump` upon
a connection failure.