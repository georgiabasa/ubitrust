#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/ecp.h>
#include <ubi_crypt/ec.h>
#include <ubi_crypt/rand.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>




int ubi_get_ec_group_bnp256(mbedtls_ecp_group **grp){
    unsigned char bnp256_p[] =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
        0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9F,
        0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x98, 0x0A, 0x82,
        0xD3, 0x29, 0x2D, 0xDB, 0xAE, 0xD3, 0x30, 0x13
    };

    unsigned char BNP256_ORDER[] =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
        0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
        0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
        0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0D
    };

    unsigned char bnp256_a[] = {0x00};
    unsigned char bnp256_b[] = {0x03};
    unsigned char bnp256_gX_[] = {0x01};
    unsigned char bnp256_gy_[] = {0x02};

    int ret = UBI_SUCCESS;

    mbedtls_mpi *P = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(P);
    mbedtls_mpi *A = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(A);
    mbedtls_mpi *B = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(B);
    mbedtls_mpi *Gx = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(Gx);
    mbedtls_mpi *Gy = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(Gy);
    mbedtls_mpi *N = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(N);
    *grp = (mbedtls_ecp_group *)calloc(1,sizeof(mbedtls_ecp_group));
    mbedtls_ecp_group_init(*grp);

    if ((ret = mbedtls_mpi_read_binary(P, bnp256_p, sizeof(bnp256_p))) != 0 ||
         (ret = mbedtls_mpi_read_binary(A, bnp256_a, sizeof(bnp256_a))) != 0 ||
         (ret = mbedtls_mpi_read_binary(B, bnp256_b, sizeof(bnp256_b))) != 0 ||
         (ret = mbedtls_mpi_read_binary(Gx, bnp256_gX_, sizeof(bnp256_gX_))) != 0 ||
         (ret = mbedtls_mpi_read_binary(Gy, bnp256_gy_, sizeof(bnp256_gy_))) != 0 ||
         (ret = mbedtls_mpi_read_binary(N, BNP256_ORDER, sizeof(BNP256_ORDER))) != 0)
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    mbedtls_mpi_init(&(**grp).P);
    mbedtls_mpi_init(&(**grp).A);
    mbedtls_mpi_init(&(**grp).B);
    mbedtls_mpi_init(&(**grp).N);

    if ((ret = mbedtls_mpi_copy(&(**grp).P, P)) != 0 ||
        (ret = mbedtls_mpi_copy(&(**grp).A, A)) != 0 ||
        (ret = mbedtls_mpi_copy(&(**grp).B, B)) != 0 ||
        (ret = mbedtls_mpi_copy(&(**grp).N, N)) != 0)
    {   
        ret = UBI_CPY_ERROR;
        goto cleanup;
    }

    (**grp).MBEDTLS_PRIVATE(h) = 1; 
    (**grp).pbits = mbedtls_mpi_bitlen(P);
    (**grp).nbits = mbedtls_mpi_bitlen(N);


    mbedtls_ecp_point_init(&(**grp).G);
    mbedtls_mpi_init(&(**grp).G.MBEDTLS_PRIVATE(X));
    mbedtls_mpi_init(&(**grp).G.MBEDTLS_PRIVATE(Y));
    mbedtls_mpi_init(&(**grp).G.MBEDTLS_PRIVATE(Z));


    if ((ret = mbedtls_mpi_copy(&(**grp).G.MBEDTLS_PRIVATE(X), Gx)) != 0 ||
        (ret = mbedtls_mpi_copy(&(**grp).G.MBEDTLS_PRIVATE(Y), Gy)) != 0 ||
        (ret = mbedtls_mpi_lset(&(**grp).G.MBEDTLS_PRIVATE(Z), 1)) != 0)
    {   
        ret = UBI_CPY_ERROR;
        goto cleanup;
    }
    
    goto cleanup;
cleanup:
    mbedtls_mpi_free(P);
    mbedtls_mpi_free(A);
    mbedtls_mpi_free(B);
    mbedtls_mpi_free(Gx);
    mbedtls_mpi_free(Gy);
    mbedtls_mpi_free(N);
    free(P);
    free(A);
    free(B);
    free(Gx);
    free(Gy);
    free(N);
    P = NULL;
    A = NULL;
    B = NULL;
    Gx = NULL;
    Gy = NULL;
    N = NULL;

    if (ret != 0) {
        mbedtls_ecp_group_free(*grp);
        free(*grp);
        *grp = NULL;
    }
    return ret;
}


int ubi_get_ecp_size(mbedtls_ecp_point *ecp, size_t *ecp_size){
    size_t ecp_x_size = mbedtls_mpi_size(&(*ecp).MBEDTLS_PRIVATE(X));
    size_t ecp_y_size = mbedtls_mpi_size(&(*ecp).MBEDTLS_PRIVATE(Y));
    size_t ecp_z_size = mbedtls_mpi_size(&(*ecp).MBEDTLS_PRIVATE(Z));

    *ecp_size = ecp_x_size+ecp_y_size+ecp_z_size;

    return UBI_SUCCESS;
}


int free_ubi_ecp_group(mbedtls_ecp_group *grp){
    mbedtls_mpi_free(&grp->P);
    mbedtls_mpi_free(&grp->A);
    mbedtls_mpi_free(&grp->B);
    mbedtls_mpi_free(&grp->N);
    mbedtls_mpi_free(&grp->G.MBEDTLS_PRIVATE(X));
    mbedtls_mpi_free(&grp->G.MBEDTLS_PRIVATE(Y));
    mbedtls_mpi_free(&grp->G.MBEDTLS_PRIVATE(Z));
    mbedtls_ecp_point_free(&grp->G);
    mbedtls_ecp_group_free(grp);
    return UBI_SUCCESS;
}


int ubi_compute_group_generator(struct ubi_compute_group_generator_in *in, struct ubi_compute_group_generator_out **out){
    int ret = UBI_SUCCESS;
    size_t olen;
    mbedtls_ecp_point *Q = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_mpi *d = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_ecp_point_init(Q);
    mbedtls_mpi_init(d);
    struct ubi_random_bytes_mod_in rand_mod_in;
    struct ubi_random_bytes_mod_out *rand_mod_out = NULL;

    mbedtls_ecp_group *grp = NULL;
    switch ((*in).curve_type) {
        case BNP_256:
            ubi_get_ec_group_bnp256(&grp);
            break;
        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }
    if (grp == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    rand_mod_in.bytes_num = mbedtls_mpi_size(&grp->N);
    rand_mod_in.mod_order = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    rand_mod_in.mod_order->buffer = calloc(mbedtls_mpi_size(&grp->N), sizeof(uint8_t));
    rand_mod_in.mod_order->buffer_len = mbedtls_mpi_size(&grp->N);
    if ((ret = mbedtls_mpi_write_binary(&grp->N, rand_mod_in.mod_order->buffer, rand_mod_in.mod_order->buffer_len)) != 0)
    {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
    if((ret = ubi_random_bytes_mod(&rand_mod_in, &rand_mod_out)) != UBI_SUCCESS){
            ret = UBI_RANDOM_BYTES_MOD_ERROR;
            goto cleanup;
    }
    
    if ((ret = mbedtls_mpi_read_binary(d, (*rand_mod_out).random_bytes_mod->buffer, (*rand_mod_out).random_bytes_mod->buffer_len)) != 0) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_ecp_mul(grp, Q, d, &grp->G, ubi_random_bytes, NULL)) != UBI_SUCCESS)
    {
        ret = UBI_ECP_MUL_ERROR;
        goto cleanup;
    }

    (*out) = (struct ubi_compute_group_generator_out *)calloc(1,sizeof(struct ubi_compute_group_generator_out));
    (**out).generator = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
    if ((**out).generator == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    ubi_get_ecp_size(Q, &(**out).generator->buffer_len);
    (**out).generator->buffer = (uint8_t *)calloc((**out).generator->buffer_len, sizeof(uint8_t));
    if ((**out).generator->buffer == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    ret = mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (**out).generator->buffer, (**out).generator->buffer_len);
    if (ret != 0) {
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }
cleanup:
    mbedtls_mpi_free(d);
    free(d);
    d = NULL;
    mbedtls_ecp_point_free(Q);
    free(Q);
    Q = NULL;
    if (rand_mod_in.mod_order != NULL) {
        if (rand_mod_in.mod_order->buffer != NULL) { free(rand_mod_in.mod_order->buffer); rand_mod_in.mod_order->buffer = NULL;}
        free(rand_mod_in.mod_order); rand_mod_in.mod_order = NULL;
    }
    free_ubi_random_bytes_mod_out(rand_mod_out);
    free_ubi_ecp_group(grp);
    free(grp);
    return ret;

}

int free_ubi_compute_group_generator_out(struct ubi_compute_group_generator_out *out){
    if (out != NULL) {
        if ((*out).generator != NULL) {
            if ((*out).generator->buffer != NULL) {
                free((*out).generator->buffer);
                (*out).generator->buffer = NULL;
            }
            free((*out).generator);
            (*out).generator = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}


int ubi_commit(struct ubi_commit_in *in, struct ubi_commit_out **out){
    int ret = UBI_SUCCESS;
    size_t olen;
    mbedtls_ecp_point *R = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point *Q = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point_init(R);
    mbedtls_ecp_point_init(Q);
    mbedtls_mpi *d = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(d);


    mbedtls_ecp_group *grp = NULL;
    switch ((*in).curve_type) {
        case BNP_256:
            ubi_get_ec_group_bnp256(&grp);
            break;
        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }
    if (grp == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    if ((ret = mbedtls_mpi_read_binary(d, (*in).commited_secret->buffer, (*in).commited_secret->buffer_len)) != UBI_SUCCESS) 
    {
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    (*out) = (struct ubi_commit_out *)calloc(1,sizeof(struct ubi_commit_out));
    (**out).commitment = (struct ubi_buffer **)calloc((*in).commit_num,sizeof(struct ubi_buffer *));    
    (**out).commit_num = (*in).commit_num;
    for(size_t i=0; i<(*in).commit_num; i++){
        
        if((ret = mbedtls_ecp_point_read_binary(grp, Q, (*in).points[i]->buffer, (*in).points[i]->buffer_len)) != UBI_SUCCESS){
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_ecp_mul(grp, R, d, Q, ubi_random_bytes, NULL)) != UBI_SUCCESS)
        {
            ret = UBI_ECP_MUL_ERROR;
            goto cleanup;
        }
        (**out).commitment[i] = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
        if ((**out).commitment[i] == NULL) {
            ret = UBI_MEM_ERROR;
            goto cleanup;
        }
        ubi_get_ecp_size(R, &(**out).commitment[i]->buffer_len);
        (**out).commitment[i]->buffer = (uint8_t *)calloc(1, (**out).commitment[i]->buffer_len * sizeof(uint8_t));
        if ((**out).commitment[i]->buffer == NULL) {
            free((**out).commitment[i]->buffer);
            ret = UBI_MEM_ERROR;
            goto cleanup;
        }
        if((ret = mbedtls_ecp_point_write_binary(grp, R, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (**out).commitment[i]->buffer, (**out).commitment[i]->buffer_len)) != UBI_SUCCESS){
            ret = UBI_WRITE_BIN_ERROR;
            goto cleanup;
        }
        
       
    }
cleanup:
    mbedtls_mpi_free(d);
    free(d);
    d = NULL;
    if (R != NULL) {mbedtls_ecp_point_free(R); free(R); R = NULL;}
    if (Q != NULL) {mbedtls_ecp_point_free(Q); free(Q); Q = NULL;}
    free_ubi_ecp_group(grp);
    free(grp);
    grp = NULL;
    return ret;
}


int free_ubi_commit_out(struct ubi_commit_out *out){
    if (out != NULL) {
        if ((*out).commitment != NULL) {
            for(size_t i=0; i<(*out).commit_num; i++){
                if ((*out).commitment[i] != NULL) {
                    if ((*out).commitment[i]->buffer != NULL) {
                        free((*out).commitment[i]->buffer);
                        (*out).commitment[i]->buffer = NULL;
                    }
                    free((*out).commitment[i]);
                    (*out).commitment[i] = NULL;
                }
            }
            free((*out).commitment);
            (*out).commitment = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}

int ubi_ec_point_add(struct ubi_ec_point_add_in *in, struct ubi_ec_point_add_out **out){
    int ret = UBI_SUCCESS;
    mbedtls_ecp_point *R = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point *Q = (mbedtls_ecp_point *)calloc(1,sizeof(mbedtls_ecp_point));
    mbedtls_ecp_point_init(R);
    mbedtls_ecp_point_init(Q);
    mbedtls_mpi *n = (mbedtls_mpi *)calloc(1,sizeof(mbedtls_mpi));
    mbedtls_mpi_init(n);
    if(mbedtls_mpi_lset(n, 1) != UBI_SUCCESS){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }    

    mbedtls_ecp_group *grp = NULL;
    switch ((*in).curve_type) {
        case BNP_256:
            ubi_get_ec_group_bnp256(&grp);
            break;
        default:
            ret = UBI_NOT_IMPLEMENTED_ERROR;
            goto cleanup;
    }
    if (grp == NULL)
    {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_ecp_point_read_binary(grp, Q, (*in).points[0]->buffer, (*in).points[0]->buffer_len)) != UBI_SUCCESS){
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    mbedtls_ecp_copy(R, Q);
    for(size_t i=1; i<(*in).points_num; i++){
        
        if((ret = mbedtls_ecp_point_read_binary(grp, Q, (*in).points[i]->buffer, (*in).points[i]->buffer_len)) != UBI_SUCCESS){
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        if ((ret = mbedtls_ecp_muladd(grp, R, n, Q, n, R)) != UBI_SUCCESS)
        {
            ret = UBI_ECP_ADD_ERROR;
            goto cleanup;
        }
    }
    (*out) = (struct ubi_ec_point_add_out *)calloc(1,sizeof(struct ubi_ec_point_add_out));
    (**out).point = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if ((**out).point == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    ubi_get_ecp_size(R, &(**out).point->buffer_len);
    (**out).point->buffer = (uint8_t *)calloc(1, (**out).point->buffer_len * sizeof(uint8_t));
    if ((**out).point->buffer == NULL) {
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if((ret = mbedtls_ecp_point_write_binary(grp, R, MBEDTLS_ECP_PF_UNCOMPRESSED, &(**out).point->buffer_len, (**out).point->buffer, (**out).point->buffer_len)) != UBI_SUCCESS){
        ret = UBI_WRITE_BIN_ERROR;
        goto cleanup;
    }   

cleanup:
    mbedtls_ecp_point_free(R);
    mbedtls_ecp_point_free(Q);
    free(R);
    free(Q);
    R = NULL;
    Q = NULL;
    free_ubi_ecp_group(grp);
    free(grp);
    grp = NULL;
    mbedtls_mpi_free(n);
    free(n);
    n = NULL;
    return ret; 
}


int free_ubi_ec_point_add_out(struct ubi_ec_point_add_out *out){
    if (out != NULL) {
        if ((*out).point != NULL) {
            if ((*out).point->buffer != NULL) {
                free((*out).point->buffer);
                (*out).point->buffer = NULL;
            }
            free((*out).point);
            (*out).point = NULL;
        }
        free(out);
        out = NULL;
    }
    return UBI_SUCCESS;
}