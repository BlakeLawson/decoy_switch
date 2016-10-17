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
** Updated version of Mininet so Mininet runs on upgraded VM kernel.
** Wrote real topo.py that executes commands on the virtual hosts.
** Changed tcpdump permissions in the test VM so that tcpdump can write log
files.
** Downloaded golang library for working with TCP headers and restructured
files so that go modules are arranged in a more go-like manner.

* (10/16) Mostly explicit TCP header manipulation.
** In set up client.go so that it sends SYN packets with custom sequence
numbers.
** Started writing p4 code to detect special tagged SYN packets.

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


TODO List
=========
* Migrate custom TCP handshake code from client.go to a separate TCP library.
* Investigate value for initial TCP congestion window
* Swap current p4 code with learning switch at https://github.com/p4lang/switch
