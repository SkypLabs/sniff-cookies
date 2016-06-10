# Sniff Cookies

[![Build Status](https://travis-ci.org/SkypLabs/sniff-cookies.svg)](https://travis-ci.org/SkypLabs/sniff-cookies)

This program allows to display HTTP cookies passing through the network which your NIC is connected.

## Dependencies

 * [libpcap][1]

### On Fedora

    dnf install make automake gcc libpcap libpcap-devel

### On Debian

    apt-get install make automake gcc libpcap0.8 libpcap-dev

## Installation

    ./autogen.sh
    ./configure
    make
    make install

## How to

To start the sniffer (as root) :

    ./sniff_cookies

Optionally, you can specify the NIC to use :

    ./sniff_cookies eth0

## License

[GPL version 3][2]

  [1]: http://www.tcpdump.org "Official web site of tcpdump and libpcap"
  [2]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"
