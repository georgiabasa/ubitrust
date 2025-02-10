#ifndef __UBI_PAIRINGS_H__
#define __UBI_PAIRINGS_H__

#include <stdlib.h>
#include <stdint.h>


typedef struct ubi_verify_bbs_pairings_in
{
    int curve_type;
    struct ubi_buffer *point2_a;
    struct ubi_buffer *point_b;
    struct ubi_buffer *point2_c;
    struct ubi_buffer *point_d;
}ubi_verify_pairings_in;

typedef struct ubi_verify_bbs_pairings_out
{
    int pairing_status;
}ubi_verify_pairings_out;

int ubi_verify_bbs_pairings(struct ubi_verify_bbs_pairings_in *in, struct ubi_verify_bbs_pairings_out *out);


#endif // __UBI_PAIRINGS_H__