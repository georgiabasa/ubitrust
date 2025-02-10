#ifndef __UBI_NUMERIC_H
#define __UBI_NUMERIC_H

#include <stdlib.h>
#include <stdint.h>
#include <ubi_common/structs.h>

typedef struct ubi_mod_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer *input;
} ubi_mod_in;

typedef struct ubi_mod_out
{
    struct ubi_buffer *output;
} ubi_mod_out;


typedef struct ubi_mod_add_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer **adder;
    size_t adder_num;
} ubi_mod_add_in;

typedef struct ubi_mod_add_out
{
    struct ubi_buffer *output;
} ubi_mod_add_out;

typedef struct ubi_mod_mul_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer **mult;
    size_t mult_num;
} ubi_mod_mul_in;

typedef struct ubi_mod_mul_out
{
    struct ubi_buffer *output;
} ubi_mod_mul_out;

typedef struct ubi_mod_inv_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer *input;
} ubi_mod_inv_in;

typedef struct ubi_mod_inv_out
{
    struct ubi_buffer *output;
} ubi_mod_inv_out;


typedef struct ubi_mod_sub_in
{
    struct ubi_buffer *mod;
    struct ubi_buffer *src;
    struct ubi_buffer *sub;
} ubi_mod_sub_in;

typedef struct ubi_mod_sub_out
{
    struct ubi_buffer *output;
} ubi_mod_sub_out;

int free_ubi_mod_out(struct ubi_mod_out *out);

int free_ubi_mod_add_out(struct ubi_mod_add_out *out);

int free_ubi_mod_mul_out(struct ubi_mod_mul_out *out);

int free_ubi_mod_inv_out(struct ubi_mod_inv_out *out);

int free_ubi_mod_sub_out(struct ubi_mod_sub_out *out);

int ubi_mod(struct ubi_mod_in *in, struct ubi_mod_out **out);

int ubi_mod_add(struct ubi_mod_add_in *in, struct ubi_mod_add_out **out);

int ubi_mod_mul(struct ubi_mod_mul_in *in, struct ubi_mod_mul_out **out);

int ubi_mod_inverse(struct ubi_mod_inv_in *in, struct ubi_mod_inv_out **out); 

int ubi_mod_sub(struct ubi_mod_sub_in *in, struct ubi_mod_sub_out **out);

#endif