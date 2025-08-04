/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal.h"
#include "crypto/mlkem-libjade/src/mlkem1024_amd64_avx2/api.h"
#include <string.h>

#define MAX_OF(a, b) ((a) > (b) ? (a) : (b))

uint8_t* __jasmin_syscall_randombytes__(uint8_t* dest, uint64_t length_in_bytes)
{
  noise_rand_bytes(dest, length_in_bytes);
  return dest;
}


typedef struct NoiseMlkemState_s
{
    struct NoiseDHState_s parent;
    /* for INITIATOR, this is the secret key.  for RESPONDER, this is the precomputed shared bytes */
    uint8_t mlkem_priv[MAX_OF(jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES, jade_kem_mlkem_mlkem1024_amd64_avx2_BYTES)];
    /* for INITIATOR, this is the public key.  for RESPONDER, this is the CIPHERTEXT */
    uint8_t mlkem_pub[MAX_OF(jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES, jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES)];
} NoiseMlkemState;

static int noise_mlkem_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    uint8_t pub_dealias[jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES];
    NoiseMlkemState *st = (NoiseMlkemState *)state;
    NoiseMlkemState *os = (NoiseMlkemState *)other;
    if (st->parent.role == NOISE_ROLE_RESPONDER) {
        /* Generating the keypair for Bob relative to Alice's parameters */
        if (!os || os->parent.key_type == NOISE_KEY_TYPE_NO_KEY)
            return NOISE_ERROR_INVALID_STATE;
        
        jade_kem_mlkem_mlkem1024_amd64_avx2_enc(
            pub_dealias,
            st->mlkem_priv,
            os->mlkem_pub);
        memcpy(st->mlkem_pub, pub_dealias,jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES);
    } else {
        /* Generate the keypair for Alice */
        jade_kem_mlkem_mlkem1024_amd64_avx2_keypair(
            st->mlkem_pub,
            st->mlkem_priv);
    }
    return NOISE_ERROR_NONE;
}

static int noise_mlkem_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    /* Private key is a concatenation of [priv_key_bytes][pub_key_bytes][pub_key_sha256] */
    NoiseMlkemState *st = (NoiseMlkemState *)state;
    if (st->parent.private_key_len != jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES)
        return NOISE_ERROR_INVALID_PRIVATE_KEY;
    memcpy(st->mlkem_priv, private_key, jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES);
    memcpy(st->mlkem_pub, private_key + jade_kem_mlkem_mlkem1024_amd64_avx2_INDCPA_SECRETKEYBYTES, jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES);
    return NOISE_ERROR_NONE;
}

static int noise_mlkem_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Ignore the public key and re-generate from the private key */
    return noise_mlkem_set_keypair_private(state, private_key);
}

static int noise_mlkem_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    // TODO: this.
    return NOISE_ERROR_NONE;
}

static int noise_mlkem_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    return NOISE_ERROR_NOT_IMPLEMENTED;
}

static int noise_mlkem_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    NoiseMlkemState *priv_st = (NoiseMlkemState *)private_key_state;
    NoiseMlkemState *pub_st = (NoiseMlkemState *)public_key_state;
    if (priv_st->parent.role == NOISE_ROLE_RESPONDER) {
        /* We already generated the shared secret for Bob when we
         * generated the "keypair" for him. */
        memcpy(shared_key, priv_st->mlkem_priv, jade_kem_mlkem_mlkem1024_amd64_avx2_BYTES);
    } else {
        /* Generate the shared secret for Alice */
        jade_kem_mlkem_mlkem1024_amd64_avx2_dec(
            shared_key,
            pub_st->mlkem_pub,
            priv_st->mlkem_priv);
    }
    return NOISE_ERROR_NONE;
}

static void noise_mlkem_change_role(NoiseDHState *state)
{
    /* Change the size of the keys based on the object's role */
    if (state->role == NOISE_ROLE_RESPONDER) {
        state->private_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_BYTES;
        state->public_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_CIPHERTEXTBYTES;
    } else {
        state->private_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES;
        state->public_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES;
    }
}

NoiseDHState *noise_mlkem_new(void)
{
    NoiseMlkemState *state = noise_new(NoiseMlkemState);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_MLKEM1024;
    state->parent.ephemeral_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_SECRETKEYBYTES;
    state->parent.public_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_PUBLICKEYBYTES;
    state->parent.shared_key_len = jade_kem_mlkem_mlkem1024_amd64_avx2_BYTES;
    state->parent.private_key = state->mlkem_priv;
    state->parent.public_key = state->mlkem_pub;
    state->parent.generate_keypair = noise_mlkem_generate_keypair;
    state->parent.set_keypair = noise_mlkem_set_keypair;
    state->parent.set_keypair_private = noise_mlkem_set_keypair_private;
    state->parent.validate_public_key = noise_mlkem_validate_public_key;
    state->parent.copy = noise_mlkem_copy;
    state->parent.calculate = noise_mlkem_calculate;
    state->parent.change_role = noise_mlkem_change_role;
    NoiseDHState* out = &(state->parent);
    return out;
}
