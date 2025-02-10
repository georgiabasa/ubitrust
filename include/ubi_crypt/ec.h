#ifndef __UBI_EC_H__
#define __UBI_EC_H__

#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/ecp.h>


typedef struct ubi_compute_group_generator_in
{
    int curve_type;
}ubi_compute_group_generator_in;
 
typedef struct ubi_compute_group_generator_out
{
    struct ubi_buffer *generator;
}ubi_compute_group_generator_out;


typedef struct ubi_commit_in
{
    int curve_type;
    struct ubi_buffer *commited_secret;
    struct ubi_buffer **points;
    size_t commit_num;
}ubi_commit_in;

typedef struct ubi_commit_out
{
    struct ubi_buffer **commitment;
    size_t commit_num;
}ubi_commit_out;

typedef struct ubi_ec_point_add_in
{
    int curve_type;
    struct ubi_buffer **points;
    size_t points_num;
}ubi_ec_point_add_in;

typedef struct ubi_ec_point_add_out
{
    struct ubi_buffer *point;
}ubi_ec_point_add_out;



int ubi_get_ec_group_bnp256(mbedtls_ecp_group **grp);

int free_ubi_ecp_group(mbedtls_ecp_group *grp);

int ubi_get_ecp_size(mbedtls_ecp_group *grp, size_t *ecp_size);

int ubi_compute_group_generator(struct ubi_compute_group_generator_in *in, struct ubi_compute_group_generator_out **out);

int free_ubi_compute_group_generator_out(struct ubi_compute_group_generator_out *out);

int ubi_commit(struct ubi_commit_in *in, struct ubi_commit_out **out);

int free_ubi_commit_out(struct ubi_commit_out *out);

int ubi_ec_point_add(struct ubi_ec_point_add_in *in, struct ubi_ec_point_add_out **out);

int free_ubi_ec_point_add_out(struct ubi_ec_point_add_out *out);

#endif

