#include <stdio.h>
#include <stdlib.h>

#include <mbedtls/ecp.h>
#include <ubi_crypt/ec.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>

void test_ubi_compute_group_generator(void);


void test_ubi_compute_group_generator(void) {
    int ret;
    struct ubi_compute_group_generator_in in;
    struct ubi_compute_group_generator_out *out = NULL;

    // Initialize the group structure
    

    // Initialize input structure
    in.curve_type = BNP_256;

    // Call the function to test
    ret = ubi_compute_group_generator(&in, &out);
    if (ret != 0) {
        printf("ubi_compute_group_generator failed: %d\n", ret);
    } else {
        printf("ubi_compute_group_generator succeeded\n");
        // Validate the output
        if (out != NULL && (*out).generator != NULL && (*out).generator->buffer != NULL && (*out).generator->buffer_len > 0) {
            printf("Generator buffer length: %zu\n", (*out).generator->buffer_len);
            printf("Generator buffer data: ");
            for (size_t i = 0; i < (*out).generator->buffer_len; i++) {
                printf("%02x", (*out).generator->buffer[i]);
            }
            printf("\n");
        } else {
            printf("Invalid generator output\n");
        }
    }

    // Clean up
    free_ubi_compute_group_generator_out(out);  
}
void test_ubi_commit(void);

void test_ubi_commit(void) {
    int ret;
    struct ubi_compute_group_generator_in gen_in;
    struct ubi_compute_group_generator_out *gen_out1 = NULL;
    struct ubi_compute_group_generator_out *gen_out2 = NULL;
    struct ubi_compute_group_generator_out *gen_out3 = NULL;

    struct ubi_commit_in commit_in;
    struct ubi_commit_out *commit_out = NULL;
    commit_in.points = (struct ubi_buffer **)calloc(3, sizeof(struct ubi_buffer *));

    // Initialize input structure for ubi_compute_group_generator
    gen_in.curve_type = BNP_256;

    // Call ubi_compute_group_generator to generate a group generator
    ret = ubi_compute_group_generator(&gen_in, &gen_out1);
    if (ret != 0) {
        printf("ubi_compute_group_generator 1 failed: %d\n", ret);
        goto cleanup;
    }
    ret = ubi_compute_group_generator(&gen_in, &gen_out2);
    if (ret != 0) {
        printf("ubi_compute_group_generator 2 failed: %d\n", ret);
        goto cleanup;
    }
    ret = ubi_compute_group_generator(&gen_in, &gen_out3);
    if (ret != 0) {
        printf("ubi_compute_group_generator 3 failed: %d\n", ret);
        goto cleanup;
    }

    uint8_t private_key_bytes[32] = {
        0x81, 0x02, 0xa8, 0xd7, 0x6c, 0xba, 0x94, 0xe1,
        0x4f, 0xa6, 0x47, 0xc7, 0xe9, 0x49, 0x19, 0x20,
        0x48, 0x2d, 0xfb, 0xf9, 0xbe, 0x04, 0x0d, 0xb7,
        0x27, 0xe6, 0x7c, 0x8e, 0x1d, 0xa1, 0xfa, 0xb2
    };
    struct ubi_buffer secret_buffer = { .buffer = private_key_bytes, .buffer_len = sizeof(private_key_bytes) };

    // Initialize input structure for ubi_commit
    commit_in.curve_type = BNP_256;
    commit_in.commited_secret = &secret_buffer;
    commit_in.commit_num = 3;
    
    if (commit_in.points == NULL) {
        printf("Memory allocation failed\n");
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    commit_in.points[0] = gen_out1->generator;
    commit_in.points[1] = gen_out2->generator;
    commit_in.points[2] = gen_out3->generator;

    // Call ubi_commit
    ret = ubi_commit(&commit_in, &commit_out);
    if (ret != 0) {
        printf("ubi_commit failed: %d\n", ret);
    } else {
        printf("ubi_commit succeeded\n");
        // Validate the output
        if (commit_out != NULL && commit_out->commitment != NULL && commit_out->commitment[0] != NULL && commit_out->commitment[0]->buffer != NULL && commit_out->commitment[0]->buffer_len > 0) {
            for(size_t j=0;j < commit_out->commit_num; j++)
            {
            printf("Commitment buffer length: %zu\n", commit_out->commitment[0]->buffer_len);
            printf("Commitment buffer data: ");
            for (size_t i = 0; i < commit_out->commitment[j]->buffer_len; i++) {
                printf("%02x", commit_out->commitment[j]->buffer[i]);
            }
            printf("\n");}
        } else {
            printf("Invalid commitment output\n");
        }
    }

cleanup:
    // Clean up
    if (gen_out1 != NULL) {
        if (gen_out1->generator != NULL) {
            if (gen_out1->generator->buffer != NULL) {
                free(gen_out1->generator->buffer);
            }
            free(gen_out1->generator);
        }
        free(gen_out1);
    }
    if (gen_out2 != NULL) {
        if (gen_out2->generator != NULL) {
            if (gen_out2->generator->buffer != NULL) {
                free(gen_out2->generator->buffer);
            }
            free(gen_out2->generator);
        }
        free(gen_out2);
    }
    if (gen_out3 != NULL) {
        if (gen_out3->generator != NULL) {
            if (gen_out3->generator->buffer != NULL) {
                free(gen_out3->generator->buffer);
            }
            free(gen_out3->generator);
        }
        free(gen_out3);
    }
    free_ubi_commit_out(commit_out);
    if (commit_in.points != NULL) {
        free(commit_in.points);
    }
}



void test_ubi_add(void);

void test_ubi_add(void) {
    int ret;
    struct ubi_compute_group_generator_in gen_in;
    struct ubi_compute_group_generator_out *gen_out1 = NULL;
    struct ubi_compute_group_generator_out *gen_out2 = NULL;
    struct ubi_compute_group_generator_out *gen_out3 = NULL;

    struct ubi_ec_point_add_in add_in;
    struct ubi_ec_point_add_out *add_out = NULL;

    // Initialize input structure for ubi_compute_group_generator
    gen_in.curve_type = BNP_256;

    // Call ubi_compute_group_generator to generate a group generator
    ret = ubi_compute_group_generator(&gen_in, &gen_out1);
    if (ret != 0) {
        printf("ubi_compute_group_generator 1 failed: %d\n", ret);
        goto cleanup;
    }
    ret = ubi_compute_group_generator(&gen_in, &gen_out2);
    if (ret != 0) {
        printf("ubi_compute_group_generator 2 failed: %d\n", ret);
        goto cleanup;
    }
    ret = ubi_compute_group_generator(&gen_in, &gen_out3);
    if (ret != 0) {
        printf("ubi_compute_group_generator 3 failed: %d\n", ret);
        goto cleanup;
    }

    
    // Initialize input structure for ubi_commit
    add_in.curve_type = BNP_256;
    add_in.points_num = 3;
    add_in.points = (struct ubi_buffer **)calloc(3, sizeof(struct ubi_buffer *));
    if (add_in.points == NULL) {
        printf("Memory allocation failed\n");
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    add_in.points[0] = gen_out1->generator;
    add_in.points[1] = gen_out2->generator;
    add_in.points[2] = gen_out3->generator;

    ret = ubi_ec_point_add(&add_in, &add_out);
    printf("ubi_ec_point_add returned: %d\n", ret);
    if(ret != 0){
        printf("ubi_ec_point_add failed: %d\n", ret);
        goto cleanup;
    }


    printf("Addition buffer length: %zu\n", add_out->point->buffer_len);
    printf("Addition buffer data: ");
    for (size_t i = 0; i < add_out->point->buffer_len; i++) {
        printf("%02x", add_out->point->buffer[i]);
    }
    printf("\n");
     
    

cleanup:
printf("Cleaning up\n");
    // Clean up
    if (gen_out1 != NULL) {
        if (gen_out1->generator != NULL) {
            if (gen_out1->generator->buffer != NULL) {
                free(gen_out1->generator->buffer);
            }
            free(gen_out1->generator);
        }
        free(gen_out1);
    }
    if (gen_out2 != NULL) {
        if (gen_out2->generator != NULL) {
            if (gen_out2->generator->buffer != NULL) {
                free(gen_out2->generator->buffer);
            }
            free(gen_out2->generator);
        }
        free(gen_out2);
    }
    if (gen_out3 != NULL) {
        if (gen_out3->generator != NULL) {
            if (gen_out3->generator->buffer != NULL) {
                free(gen_out3->generator->buffer);
            }
            free(gen_out3->generator);
        }
        free(gen_out3);
    }
    free_ubi_ec_point_add_out(add_out);
    free(add_in.points);
    
}

void print_ecp_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *point);

void print_ecp_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *point) {
    size_t olen;
    uint8_t buffer[MBEDTLS_ECP_MAX_PT_LEN];

    // Convert the point to a buffer
    int ret = mbedtls_ecp_point_write_binary(grp, point, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buffer, sizeof(buffer));
    if (ret != 0) {
        printf("Failed to convert point to buffer: %d\n", ret);
        return;
    }

    // Print the buffer
    printf("Point G: ");
    for (size_t i = 0; i < olen; i++) {
        printf(",0x%02x", buffer[i]);
    }
    printf("\n");
}


int main(void) {
    mbedtls_ecp_group *grp = NULL;

    // Test the get_ec_group_bnp256 function
    int ret = ubi_get_ec_group_bnp256(&grp);
    if (ret == 0) {
        
        printf("Elliptic curve group BNP256 initialized successfully.\n");
        print_ecp_point(grp, &grp->G);
        free_ubi_ecp_group(grp);
        free(grp);
    } else {
        printf("Failed to initialize elliptic curve group BNP256.\n");
    }
    test_ubi_compute_group_generator();
    test_ubi_commit();

    test_ubi_add();

    return ret;
}
