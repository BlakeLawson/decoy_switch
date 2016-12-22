/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Standard actions used in all p4 modules.
 */
action _no_op() {
  no_op();
}

action _drop() {
  drop();
}
