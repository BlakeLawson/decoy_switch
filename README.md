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
* (10/12) Lots of time spent debugging test environment. By the end of the day,
managed to get environment working and could send normal requests to/from
client and server.
  * Updated version of Mininet so Mininet runs on upgraded VM kernel.
  * Wrote real topo.py that executes commands on the virtual hosts.
  * Changed tcpdump permissions in the test VM so that tcpdump can write log
files.
  * Downloaded golang library for working with TCP headers and restructured
files so that go modules are arranged in a more go-like manner.

* (10/16) Mostly explicit TCP header manipulation.
  * In set up client.go so that it sends SYN packets with custom sequence
numbers.
  * Started writing p4 code to detect special tagged SYN packets.

* (10/18) Getting P4 switch to work in mininet + Meeting with Jen.
  * P4 code compiles and executes (abit incorrectly) in the mininet test
environment. Not clear why P4 program not executing correctly.

Week 10/19 - 10/25
------------------
* Replace explicit client code with P4 program that overwrites OS seq number
with custom, decoy switch seq.

* (10/19) Debugging P4 program
  * Fixed P4 vim syntax highlighting (bug in file from bearfoot. Fix pushed
upstream)
  * Determined that P4 code not executing because switch does not support ARP
* (10/20) Fixing P4 program and working on tag detection
  * Added support for ARP queries. P4 Program functions as expected.
  * P4 tag detection code written. Currently figuring out the best way to
reroute packets to the proxy.
* (10/22) More tag detection and P4 routing
  * Finished writing code for tag detection and rerouting in P4
  * Write client code to encode tag in SYN SEQ number
  * Issues while debugging. Next step is finding this bug (error using P4 CLI)
* (10/25) Debuggin tag detection
  * Fixed problems from 10/22. That is, p4 code executes and ARP queries work
again. Tag not getting detected though.

Week 10/26 - 11/8
-----------------
* (11/3) Tag detection
  * Determined that tag detection was not working because the implementation of
`modify_field_with_hash_based_offset` was incorrect in the virtual switch
provided in the P4 Github repo.
  * Fixed bug in implementation of `modify_field_with_hash_based_offset` and
pushed change upstream.
* (11/4) Tag detection
  * After debugging the tag calculation in the client-side Go code, decided
it is not worth the time. Transitioning to writing P4 client instead.
  * Successfully tagging packets in P4 and detecting tag at decoy switch.

Design Decisions
================


Tagging
-------
(10/11) Right now, it doesn't look like any of the tagging techniques outlined
in the decoy routing paper, the telex paper, or the cirripede paper will be
straightforward to implement using p4. Of the three, cirripede's method is most
likely to work (it stores the tag in the initial TCP sequence number), but for
the time being, the plan is to use a "dummy" tag that is rather easy to detect
until most of the other decoy switch functionality is complete.

It should be noted that the current solution to this problem is to write
custom TCP packets on a raw socket. Hopefully it will be possible to wrap the
raw socket in another socket after the TCP handshake, but it is not clear
whether this will work. If it does not, it will be sufficient to write only the
necessary parts of TCP for testing purposes and note that in future
implementations, this should be more robust.

(10/18) Another solution is to do the tagging in a separate P4 program that
runs on the client's machine. This should be a lot easier than implementing TCP.


ARP Queries
-----------
(10/20) The P4 sample L3 switch that my P4 code is based on did not support ARP,
queries, so I added rudimentary support for ARP as follows: since the current
mininet topology is hardcoded into the P4 routing tables, and the switch has
complete knowledge of the network, there is no reason to broadcast ARP queries.
Instead, whenever the switch receives an ARP request, it spoofs a response from
the target host that the sender is trying to query that gives the target's mac
and ip.


TODO List
=========
* Migrate P4 ARP query code to separate module.
* Migrate custom TCP handshake code from client.go to a separate TCP library.
* Investigate value for initial TCP congestion window
* Swap current p4 code with learning switch at https://github.com/p4lang/switch
