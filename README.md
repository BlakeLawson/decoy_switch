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
environment.

Week 10/19 - 10/25
-------------------------
* Replace explicit client code with P4 program that overwrites OS seq number
with custom, decoy switch seq.

Design Decisions
================


Tagging
-------
Right now, it doesn't look like any of the tagging techniques outlined in the
decoy routing paper, the telex paper, or the cirripede paper will be
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

Another solution is to do the tagging in a separate P4 program that runs on the
client's machine. This should be a lot easier than implementing TCP.

TODO List
=========
* Migrate custom TCP handshake code from client.go to a separate TCP library.
* Investigate value for initial TCP congestion window
* Swap current p4 code with learning switch at https://github.com/p4lang/switch
