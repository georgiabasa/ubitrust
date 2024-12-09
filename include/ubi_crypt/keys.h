#ifndef __UBI_KEYS_H
#define __UBI_KEYS_H

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/macros.h>


typedef struct ubi_compute_public_key_in
{
    int curve_type;
    struct ubi_buffer *private_key;
}ubi_compute_public_key_in;
 
typedef struct ubi_compute_public_key_out
{
    struct ubi_buffer *public_key;
}ubi_compute_public_key_out;

typedef struct ubi_create_attestation_key_in
{
    int curve_type;
    struct ubi_buffer *policy;
}ubi_create_attestation_key_in;
 
typedef struct ubi_create_attestation_key_out
{
    struct ubi_buffer *seed;
    struct ubi_buffer *hash_private_key;
    struct ubi_buffer *name;
    struct ubi_buffer *public_key;
}ubi_create_attestation_key_out;

typedef struct ubi_load_attestation_key_in
{
    struct ubi_buffer *policy;
    struct ubi_buffer *seed;
    struct ubi_buffer *hash_private_key;

}ubi_load_attestation_key_in;
 
typedef struct ubi_load_attestation_key_out
{
    struct ubi_buffer *private_key;
}ubi_load_attestation_key_out;



typedef struct ubi_create_migratable_key_in
{
    int curve_type;
    struct ubi_buffer *policy;
}ubi_create_migratable_key_in;
 
typedef struct ubi_create_migratable_key_out
{
    struct ubi_buffer *encrypted_private_key;
    struct ubi_buffer *hash_private_key;
    struct ubi_buffer *name;
    struct ubi_buffer *public_key;
    uint8_t iv[IV_SIZE];
}ubi_create_migratable_key_out;


typedef struct ubi_load_migratable_key_in
{
    struct ubi_buffer *encrypted_private_key;
    struct ubi_buffer *hash_private_key;
    struct ubi_buffer *policy;
    uint8_t iv[IV_SIZE];
}ubi_load_migratable_key_in;
 
typedef struct ubi_load_migratable_key_out
{
    struct ubi_buffer *private_key;
}ubi_load_migratable_key_out;


void free_ubi_create_attestation_key_out(struct ubi_create_attestation_key_out *out);

void free_ubi_load_attestation_key_out(struct ubi_load_attestation_key_out *out);

void free_ubi_create_migratable_key_out(struct ubi_create_migratable_key_out *out); 

void free_ubi_load_migratable_key_out(struct ubi_load_migratable_key_out *out);

void free_ubi_compute_public_key_out(struct ubi_compute_public_key_out *out);

int ubi_compute_public_key(struct ubi_compute_public_key_in *in, struct ubi_compute_public_key_out **out);

int ubi_create_attestation_key(struct ubi_create_attestation_key_in *in, struct ubi_create_attestation_key_out **out);

int ubi_load_attestation_key(struct ubi_load_attestation_key_in *in, struct ubi_load_attestation_key_out **out);

int ubi_create_migratable_key(struct ubi_create_migratable_key_in *in, struct ubi_create_migratable_key_out **out);

int ubi_load_migratable_key(struct ubi_load_migratable_key_in *in, struct ubi_load_migratable_key_out **out);

#endif