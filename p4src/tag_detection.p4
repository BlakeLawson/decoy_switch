/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 * 
 * Rewrite dest IP if hidden tags in TLS ClientHello detected.
 */

parser start {

}

action _drop() {
  drop()
}

control ingress {

}

control egress {

}
