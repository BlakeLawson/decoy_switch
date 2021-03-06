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
* (10/25) Debugging tag detection
  * Fixed problems from 10/22. That is, P4 code executes and ARP queries work
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
* (11/6) Marking flows in P4
  * Realized that the old plan to use bloom filters alone to tag flows for
decoy switching was too simplistic because it did not provide a way to send
packets to the client that include the covert destination.
  * Researched how to offload processing to a controller using the example
P4 NAT and the basic CPU offloading example.
  * Wrote code to configure test environment for CPU offloading.
  * Also fixed a bug in my pull request to the P4 CLI repo (bmv2).
* (11/7) Started writing CPU offloading code in `tag_detection.p4`.
* (11/8) Continued writing CPU offloading in `tag_detection.p4` and started
testing.
  * Switch controller properly receiving packets. Rules not do not seem to
install properly because the overall program is not working as expected.

Week 11/9 - 11/15
-----------------
Goals: End-to-end tag detection. Reread papers and make detailed plan for decoy
switch system that specifically includes how the client communicates the covert
destination to decoy switch.

* (11/10) CPU offloading debugging
  * CPU offloading working correctly. Able to send tagged request from client
to decoy destination. Decoy switch detects and sends to proxy. Proxy response
goes back to client.
  * Started designing specifics of connection hijack and how to communicate
covert destination.
  * Started writing client switch code to remap sequence numbers after tagging.
* (11/11) Finished writing client code to remap sequence numbers after tagging.
Almost done debugging.
* (11/14) Project planning
  * Reread Cirripede, decoy routing, and Telex to review the way that they do
tagging and communicate the covert destination to the anticensorship system.
  * Decided to use same assumptions as decoy routing. That is, assume that the
client and decoy proxy share a secret key ahead of time and have decoy switch
hijack TCP connection after TLS handshake completes.

Week 11/16 - 11/22
------------------
* (11/16) Finished debugging client seqNo/ackNo remapping.
* (11/17) Expanded testing code in client.go and server.go to make tests more
realistic.
  * The servers (decoy and covert) server webpages.
  * The client requests the covert destination using HTTP proxy protocol.
  * Fixed bug in code to remap seqNo/ackNo caused by negative difference
between tag and seq number. Solved using new actions in client_switch.p4.
* (11/18) More work on testing framework.
  * Integrated real proxy for decoy proxy.
  * Started writing decoy switch in Python for testing/measurement.
* (11/19 and 11/20) More work debugging Python switch. Still not working. I
know that the problem has to do with the mininet configuration but debugging is
slow without documentation.
* (11/22) Still debugging software switch. It seems like the covert and decoy
destinations just stop working when the client switch is being used. Not clear
why this would happen because those hosts are the same whether or not the
software switch is used. Mininet is so frustrating...

Week 11/23 - 11/29
------------------
* (11/23) More debugging software client. No clear progress. Probably going to
work on something else for a while.
* (11/26) Worked on software switch
  * Figured out why baseline switch not working! (scapy is dumb)
  * Started working on the tag detection aspect of the switch. Down the rabbit
hole trying to compute the tag the same as P4.
* (11/28) More work on software switch.
  * Figured out how to calculate the tag in Python!
  * Wrote remaining code for Python decoy switch and started debugging.
  * Started working on final paper. Mostly set up Latex formatting.
* (11/29) More work on debugging and more paper set up.

Week 11/30 - 12/6
-----------------
* (11/30) Worked on introduction of paper.
* (12/1) Paper + coding
  * Finished up introduction for now and started working on background section.
  * Debugging why Python switch not working. Very confused. Python switch sends
packets identical to those from the P4 switch, but the proxy and covert dst
don't accept the connections.
* (12/2) Paper + emailed Jen about debugging issues
* (12/3) Planned changes to switch to remove need for separate proxy, and
drafted Telex background information for the paper.
* (12/4) Mostly worked on implementing changes to switch to remove proxy.
  * Refactored P4 code so easier to work with. Client switch and decoy switch
in separate directories, and moved a bunch of code in the decoy switch into
other files to make code more modular.
  * Created module for decoy switch that tracks state of TCP handshake with
decoy destination using bloom filters.
  * Modified client switch so it does not forward tagged packets until they are
added to the client's match action tables through the controller. Previously
sent and added to table simultaneously.
  * Starting debugging tagging module.
  * Started writing background on Cirripede in final paper.
* (12/5) More work removing proxy
  * Finished debugging tagging module with TCP handshake detection.
  * Finished Cirripede background section and added figures for background
section.
* (12/6) Removing proxy
  * Modified decoy controller so it extracts the ip address of the covert
destination and updates tables accordingly.
  * Added logic in P4 to get covert destination from the controller and close
the connection to the decoy destination (tested and works).
  * Mapped out logic for implementing decoy handshake/connection takeover in
P4.

Week 12/7 - 12/13
-----------------
* (12/7) General Work
  * Met with Rob for help debugging Python switch. No special insights. He
suggested looking at the TCP state machine to figure out why RST,ACK could
follow a SYN. He also recommended making my work Mininet Switch class for the
Python switch since Mininet may configure its network map differently.
  * Fixed a bug in code from yesterday that effected the way RST packets were
generated. Now all interactions with the decoy destination concluded and ready
to set up connection to the covert destination.
  * Started working on making connection to covert destination. Ran into minor
roadblock because the version of P4 in my test environment does not support
a function in the P4 spec (clone_ingress_pkt_to_ingress).
  * Wrote about half of the background information on P4 for my final paper.
Also read several one-semester IW papers from past years and feeling like I
wrote a little too much on Decoy Routing, Telex, and Cirripede.
* (12/8) Wrote more about P4 in paper.
* (12/9) More work to remove proxy and work on submission stuff.
  * Finished subsection on P4 in the paper and finished the background section
of paper.
  * Started working on presentation slides for next week.
  * Got the decoy switch to send SYN packet to covert as well as RST packet to
the decoy destination. For some reason the SYN packet isn't getting truncated
and it still contains the GET request from the client.. Need to figure that
out. As an aside, dealing with the P4 virtual switch can be a pain because it
does not always conform to the spec. This time had issues because I wasn't
cloning the packet using a mirrored port.
* (12/10) Worked on presentation for next week. Made diagrams that can be used
in presentation and the paper.

Week 12/14 - End of semester
----------------------------
* (12/14 and 12/15) Final preparation for presentation and presentation.
* (12/16 - 12/22) Off and on work on prototype and some paper writing. Finished
the prototype on 12/22!


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


Connect Hijacking and Covert Destinations
-----------------------------------------
(11/14) After rereading anticensorship papers, determined that most of those
systems use the TLS ClientHello random field to convey information to request
use of system and information for key generation. Rather then dealing with
modifications to OpenSSL or other TLS libraries, decided to use TCP seq number
to request use of decoy switching system with the understanding that this can
be improved in the future.

Also decided to use assume that the client and the decoy switch share a secret
key ahead of time, which is the same assumption that the decoy routing paper
makes. This simplified the initial configuration, and as with tagging, it is
something that can be improved down the road.

To communicate the covert destination, the plan is to hijack the connection to
the decoy destination once the TLS handshake completes and switch to using the
shared secret key (will likely need some modification to TLS library to do
this). Once connection established and encrypted using shared key, client is
free to initiate HTTPS proxy protocol or SOCKS proxy protocol to connect to the
covert destination using the decoy switch as a proxy.


TCP Options
-----------
(12/22) Following Telex's lead and not handling them. For now, getting around
the issue by saving the TCP options in the initial SYN packet to the decoy
destination and reusing those options in the SYN to the covert destination.


TODO List
=========
* Migrate P4 ARP query code to separate module.
* Finish debugging connection through client switch
* Add logic to decoy switch to detect end of TLS handshake and hijack
connection. To do this, it will be necessary to move some of the logic to the
controller for the TLS stuff.
* Modify client so it can switch to use the shared secret key after the decoy
switch hijacks the connection.
* Generate the shared switch.
