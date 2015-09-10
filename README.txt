NOT YET FINISHED

This is an implementation of ed25519 in lisp.

The goal is to be able to verify signatures from within lisp.  This implementation is *not* secure against side-channel attacks, so no operations using the private key should be performed while an attacker could potentially observe timings.
