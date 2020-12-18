# Thom's Implementation of TCP

Inspired by [Jon Gjengset's](https://www.youtube.com/playlist?list=PLqbS7AVVErFivDY3iKAQk3_VAm8SXwt1X) excellent YouTube stream. [Original code here](https://github.com/jonhoo/rust-tcp).

Also inspired by wanting to print out TCP packets, to get a better feel for the protocol.

## Progress

- [x] Basic printing of packets
- [x] Passive open
- [x] Basic state handling for arriving segments
- [ ] User APIs: `TcpListener`, `TcpStream`
- [ ] Closing connections
- [ ] Active open
- [ ] Initial Sequence Number selection
- [ ] Window management
- [ ] Retransmission
- [ ] CLI options (listen, connect, printing options etc.)
- [ ] Send/receive data
- [ ] Improved packet printing
- [ ] TCP Options
- [ ] Remote address validation
- [ ] Reordering packets (handling out of order segments)
- [ ] Proper IPv6 handling
- [ ] [Check requirements](https://datatracker.ietf.org/doc/html/draft-ietf-tcpm-rfc793bis-19#appendix-B)

## Resources

- [RFC 793 - TRANSMISSION CONTROL PROTOCOL](https://tools.ietf.org/html/rfc793)
- [RFC 1122 - Requirements for Internet Hosts -- Communication Layers](https://tools.ietf.org/html/rfc1122)
- [RFC 6528 - Defending against Sequence Number Attacks](https://tools.ietf.org/html/rfc6528)
- [RFC 7414 - A Roadmap for Transmission Control Protocol (TCP) Specification Documents](https://tools.ietf.org/html/rfc7414)
- [TCP in a nutshell](https://www.cs.miami.edu/home/burt/learning/Csc524.032/notes/tcp_nutshell.html)
- [Transmission Control Protocol (TCP) Specification (draft-ietf-tcpm-rfc793bis-19)](https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/)
- [TCP, UDP, and Sockets: rigorous and experimentally-validated behavioural specification Volume 1: Overview](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-624.pdf)
- [TCP, UDP, and Sockets: rigorous and experimentally-validated behavioural specification Volume 1: The Specification](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-625.pdf)
