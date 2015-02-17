# Sniff Cookies

This program allows to display HTTP cookies passing through the network which your NIC is connected.

## Dependencies

 * [libpcap][1] (tested with v1.5.3)

### On Fedora

    yum install libpcap libpcap-devel

### On Debian

    aptitude install libpcap0.8 libpcap-dev

## How to

    sudo ./sniff_cookies

Optionally, you can specify the NIC to use :

    sudo ./sniff_cookies eth0

## License

[GPL version 3][2]

  [1]: http://www.tcpdump.org "Official web site of tcpdump and libpcap"
  [2]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"
