#ifndef __UBI_EC2_H__
#define __UBI_EC2_H__

#include <stdlib.h>
#include <stdint.h>


typedef struct ubi_compute_group_generator2_in
{
    int curve_type;
}ubi_compute_group_generator2_in;

typedef struct ubi_compute_group_generator2_out
{
    struct ubi_buffer *generator;
}ubi_compute_group_generator2_out;


typedef struct ubi_commit2_in
{
    int curve_type;
    struct ubi_buffer *commited_secret;
    struct ubi_buffer **points;
    size_t commit_num;
}ubi_commit2_in;

typedef struct ubi_commit2_out
{
    struct ubi_buffer **commitment;
    size_t commit_num;
}ubi_commit2_out;


typedef struct ubi_ec2_point_add_in
{
    int curve_type;
    struct ubi_buffer **points;
    size_t points_num;
}ubi_ec2_point_add_in;

typedef struct ubi_ec2_point_add_out
{
    struct ubi_buffer *point;
}ubi_ec2_point_add_out;

int free_ubi_compute_group_generator2_out(struct ubi_compute_group_generator2_out *out);

int free_ubi_commit2_out(struct ubi_commit2_out *out);

int free_ubi_ec2_point_add_out(struct ubi_ec2_point_add_out *out);

int ubi_compute_group_generator2(struct ubi_compute_group_generator2_in *in, struct ubi_compute_group_generator2_out **out);

int ubi_commit2(struct ubi_commit2_in *in, struct ubi_commit2_out **out);

int ubi_ec2_point_add(struct ubi_ec2_point_add_in *in, struct ubi_ec2_point_add_out **out);


#endif // __UBI_EC2_H__