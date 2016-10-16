Third Party Documentation
=========================

This file documents general information about third party libraries that this
project uses. For every library include why/how it is used and all
modifications made to the code.

tcpHeaders (https://github.com/grahamking/latency):
----------------------------------------------------

This library is used to write custom TCP headers over a raw socket. The library
contains tcp.go, which provides TCP header parsing/writing functions.

Changes:
* Changed package name from "main" to "tcpHeaders" so the code can be imported.
* Modified to4byte function in latency.go so that is a public function.
