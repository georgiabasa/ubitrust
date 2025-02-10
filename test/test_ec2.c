#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_crypt/ec2.h>
#include <ubi_common/macros.h>

void test_ubi_ec2_generator(void);

void test_ubi_ec2_generator(void) {
    struct ubi_compute_group_generator2_in in;
    in.curve_type = BNP_256;
    struct ubi_compute_group_generator2_out *out = NULL;
    int ret = ubi_compute_group_generator2(&in, &out);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    printf("Generator: ");
    for (size_t i = 0; i < (*out).generator->buffer_len; i++) {
        printf("%02x", (*out).generator->buffer[i]);
    }
    printf("\n");
    free_ubi_compute_group_generator2_out(out);
}


void test_ubi_commit2(void);

void test_ubi_commit2(void){
    struct ubi_compute_group_generator2_in in_generator;
    in_generator.curve_type = BNP_256;
    struct ubi_compute_group_generator2_out *out_generator1 = NULL;
    struct ubi_compute_group_generator2_out *out_generator2 = NULL;
    struct ubi_compute_group_generator2_out *out_generator3 = NULL;

    int ret = ubi_compute_group_generator2(&in_generator, &out_generator1);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    ret = ubi_compute_group_generator2(&in_generator, &out_generator2);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    ret = ubi_compute_group_generator2(&in_generator, &out_generator3);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    uint8_t private_key_bytes[32] = {
        0x81, 0x02, 0xa8, 0xd7, 0x6c, 0xba, 0x94, 0xe1,
        0x4f, 0xa6, 0x47, 0xc7, 0xe9, 0x49, 0x19, 0x20,
        0x48, 0x2d, 0xfb, 0xf9, 0xbe, 0x04, 0x0d, 0xb7,
        0x27, 0xe6, 0x7c, 0x8e, 0x1d, 0xa1, 0xfa, 0xb2
    };
    struct ubi_buffer secret_buffer = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };

    ubi_commit2_in in;
    ubi_commit2_out *out = NULL;
    in.curve_type = BNP_256;
    in.points = (ubi_buffer **)calloc(3, sizeof(ubi_buffer *));
    in.points[0] = out_generator1->generator;
    in.points[1] = out_generator2->generator;
    in.points[2] = out_generator3->generator;
    in.commit_num = 3;
    in.commited_secret = &secret_buffer;
    ret = ubi_commit2(&in, &out);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_commit2: %d\n", ret);
        return;
    }
    for (size_t i = 0; i < (*out).commit_num; i++) {
        printf("Commitment %zu: ", i);
        for (size_t j = 0; j < (*out).commitment[i]->buffer_len; j++) {
            printf("%02x", (*out).commitment[i]->buffer[j]);
        }
        printf("\n");
    }



    free_ubi_compute_group_generator2_out(out_generator1);
    free_ubi_compute_group_generator2_out(out_generator2);
    free_ubi_compute_group_generator2_out(out_generator3);
    free_ubi_commit2_out(out);
    free(in.points);

}

void test_ubi_ec2_point_add(void);

void test_ubi_ec2_point_add(void){

    struct ubi_compute_group_generator2_in in_generator;
    in_generator.curve_type = BNP_256;
    struct ubi_compute_group_generator2_out *out_generator1 = NULL;
    struct ubi_compute_group_generator2_out *out_generator2 = NULL;
    struct ubi_compute_group_generator2_out *out_generator3 = NULL;

    int ret = ubi_compute_group_generator2(&in_generator, &out_generator1);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    ret = ubi_compute_group_generator2(&in_generator, &out_generator2);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    ret = ubi_compute_group_generator2(&in_generator, &out_generator3);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_compute_group_generator2: %d\n", ret);
        return;
    }
    struct ubi_ec2_point_add_in in;
    struct ubi_ec2_point_add_out *out = NULL;
    in.curve_type = BNP_256;
    in.points = (ubi_buffer **)calloc(3, sizeof(ubi_buffer *));
    in.points[0] = out_generator1->generator;
    in.points[1] = out_generator2->generator;
    in.points[2] = out_generator3->generator;
    in.points_num = 3;
    ret = ubi_ec2_point_add(&in, &out);
    if (ret != UBI_SUCCESS) {
        printf("Error in ubi_ec2_point_add: %d\n", ret);
        // return;
    }
    else{
    printf("Result: ");
    for (size_t i = 0; i < (*out).point->buffer_len; i++) {
        printf("%02x", (*out).point->buffer[i]);
    }
    printf("\n");
    }
    free(in.points);
    free_ubi_ec2_point_add_out(out);
    free_ubi_compute_group_generator2_out(out_generator1);
    free_ubi_compute_group_generator2_out(out_generator2);
    free_ubi_compute_group_generator2_out(out_generator3);
}

int main(void) {
    test_ubi_ec2_generator();

    test_ubi_commit2();

    test_ubi_ec2_point_add();
    return 0;
}