Current progress and plans
===========================


Week 10/4 - 10/11
-----------------

On tagging and detection:

Fairly uncertain about the best way to implement secure tags in P4 or on the
client, so right now, planning to punt on that and make a client that performs
a modified TLS handshake that includes some secret key in the random bits
field.

Steps:
* Make client that does nothing but send basic packets with modification
* Make P4 program that parses packets for special string
* Make Mininet topology that includes three hosts and a switch where the switch runs P4.


Week 10/11 - 10/18
------------------


Design Decisions
================


Tagging
-------



TODO List
=========
* Migrate custom TCP handshake code from client.go to a separate TCP library.
* Investigate value for initial TCP congestion window
