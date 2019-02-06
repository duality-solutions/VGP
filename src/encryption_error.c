#include "encryption_error.h"

const char* bdap_error_message[] =
{
    "",
    "Unknown error has occurred",
    "Unable to convert Ed25519 public-key to Curve25519 public key",
    "Unable to obtain Curve25519 public-key from its private-key",
    "Unable to derive a Curve25519 key-pair",
    "Unable to perform Curve25519 Diffie-Hellman exchange",
    "AES-CTR key and IV derivation failed",
    "AES-GCM key and nonce derivation failed",
    "AES-CTR encrypt failed",
    "AES-CTR decrypt failed",
    "AES-GCM encrypt failed",
    "AES-GCM decrypt failed",
    "Unable to find a valid recipient's encrypted secret",
    "Memory protection failed"
};
