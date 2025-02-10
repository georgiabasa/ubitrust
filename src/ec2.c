#include <stdlib.h>
#include <stdint.h>

#include <ecp2_FP256BN.h>
#include <big_256_56.h>


#include <ubi_crypt/ec2.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


int ubi_compute_group_fp256_generator2(struct ubi_compute_group_generator2_in *in, struct ubi_compute_group_generator2_out **out);

int ubi_compute_group_fp256_generator2(struct ubi_compute_group_generator2_in *in, struct ubi_compute_group_generator2_out **out){
    int ret = UBI_SUCCESS;
    ECP2_FP256BN *core_generator = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    if(core_generator == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    if(!ECP2_FP256BN_generator(core_generator)){
        ret = UBI_EC2_GENERATOR_ERROR;
        goto cleanup;
    }
    octet *octet_generator = (octet *)calloc(1,sizeof(octet));
    if(octet_generator == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (*octet_generator).val = (char *)calloc(ECP2_FP256BN_LENGTH, sizeof(char));
    ECP2_FP256BN_toOctet(octet_generator, core_generator, false);
    (*out) = (struct ubi_compute_group_generator2_out *)calloc(1, sizeof(struct ubi_compute_group_generator2_out));
    if((*out) == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).generator = (struct ubi_buffer *)calloc(1, sizeof(struct ubi_buffer));
    if((**out).generator == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).generator->buffer = (uint8_t *)(*octet_generator).val;
    (**out).generator->buffer_len = (size_t)(*octet_generator).len;
cleanup:
        if(core_generator != NULL){ free(core_generator);}
        if(octet_generator != NULL){ free(octet_generator); }
        if(ret!= UBI_SUCCESS && (*out) != NULL){
            if((**out).generator != NULL){
                if((**out).generator->buffer != NULL){
                    free((**out).generator->buffer);
                }
                free((**out).generator);
            }
            free((*out));
        }
    return ret;
}

int free_ubi_compute_group_generator2_out(struct ubi_compute_group_generator2_out *out){
    if(out == NULL){
        return UBI_SUCCESS;
    }
    if((*out).generator != NULL){
        if((*out).generator->buffer != NULL){
            free((*out).generator->buffer);
        }
        free((*out).generator);
    }
    free(out);
    return UBI_SUCCESS;
}

int ubi_compute_group_generator2(struct ubi_compute_group_generator2_in *in, struct ubi_compute_group_generator2_out **out){
    int ret = UBI_SUCCESS;
    switch ((*in).curve_type)
    {
    case BNP_256:
        ret = ubi_compute_group_fp256_generator2(in, out);
        break;
    
    default:
        ret = UBI_NOT_IMPLEMENTED_ERROR;
        break;
    }
    return ret;
}

int ubi_commit2_fp256(struct ubi_commit2_in *in, struct ubi_commit2_out **out);

int ubi_commit2_fp256(struct ubi_commit2_in *in, struct ubi_commit2_out **out){
    int ret  = UBI_SUCCESS;
    octet *octet_commitment = (octet *)calloc(1,sizeof(octet));
    if(octet_commitment == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    ECP2_FP256BN *core_commitment = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    if(core_commitment == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    BIG_256_56 *core_secret = (BIG_256_56 *)calloc(1,sizeof(BIG_256_56));
    if(core_secret == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }

    BIG_256_56_fromBytes(*core_secret, (char *)(*in).commited_secret->buffer);
    (*out) = (struct ubi_commit2_out *)calloc(1,sizeof(struct ubi_commit2_out));
    if((*out) == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).commitment = (struct ubi_buffer **)calloc((*in).commit_num,sizeof(struct ubi_buffer *));
    if((**out).commitment == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    octet *octet_point = (octet *)calloc(1,sizeof(octet));
    for(size_t i=0; i<(*in).commit_num; i++){
        (*octet_point).val = (char *)(*in).points[i]->buffer;
        (*octet_point).len = (int)(*in).points[i]->buffer_len;
        if(!ECP2_FP256BN_fromOctet(core_commitment, octet_point)){
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        ECP2_FP256BN_mul(core_commitment, *core_secret);
        (*octet_commitment).val = (char *)calloc(ECP2_FP256BN_LENGTH, sizeof(char));
        if((*octet_commitment).val == NULL){
            ret = UBI_MEM_ERROR;
            goto cleanup;
        }
        ECP2_FP256BN_toOctet(octet_commitment, core_commitment, false);

        (**out).commitment[i] = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
        if((**out).commitment[i] == NULL){
            ret = UBI_MEM_ERROR;
            goto cleanup;
        }
        (**out).commitment[i]->buffer = (uint8_t *)(*octet_commitment).val;
        (**out).commitment[i]->buffer_len = (size_t)(*octet_commitment).len;
    }
    (**out).commit_num = (*in).commit_num;

cleanup:
    if(core_commitment != NULL){ free(core_commitment);}
    if(core_secret != NULL){ free(core_secret);}
    if(octet_commitment != NULL){ free(octet_commitment); }
    if(octet_point != NULL){ free(octet_point); }

    return ret;
}


int ubi_commit2(struct ubi_commit2_in *in, struct ubi_commit2_out **out){
    int ret = UBI_SUCCESS;
    switch ((*in).curve_type)
    {
    case BNP_256:
        ret = ubi_commit2_fp256(in, out);
        break;
    
    default:
        ret = UBI_NOT_IMPLEMENTED_ERROR;
        break;
    }
    return ret;
}

int free_ubi_commit2_out(struct ubi_commit2_out *out){
    if(out == NULL){
        return UBI_SUCCESS;
    }
    if((*out).commitment != NULL){
        for(size_t i=0; i<(*out).commit_num; i++){
            if((*out).commitment[i] != NULL){
                if((*out).commitment[i]->buffer != NULL){
                    free((*out).commitment[i]->buffer);
                }
                free((*out).commitment[i]);
            }
        }
        free((*out).commitment);
    }
    free(out);
    return UBI_SUCCESS;
}

int ubi_ec2_point_add_fp256(struct ubi_ec2_point_add_in *in, struct ubi_ec2_point_add_out **out);

int ubi_ec2_point_add_fp256(struct ubi_ec2_point_add_in *in, struct ubi_ec2_point_add_out **out){
    int ret = UBI_SUCCESS;
    ECP2_FP256BN *R = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    ECP2_FP256BN *Q = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    octet *octet_q = (octet *)calloc(1,sizeof(octet));
    octet *octet_r = NULL;
    for(size_t i=0; i<(*in).points_num; i++){
        (*octet_q).val = (char *)(*in).points[i]->buffer;
        (*octet_q).len = (int)(*in).points[i]->buffer_len;
        if(!ECP2_FP256BN_fromOctet(Q, octet_q)){
            ret = UBI_READ_BIN_ERROR;
            goto cleanup;
        }
        if(i == 0){
            ECP2_FP256BN_copy(R, Q);
        }else{
            if(ECP2_FP256BN_add(R, Q)){
                ret = UBI_EC2_POINT_ADD_ERROR;
                goto cleanup;
            }
        }
    }
    (*out) = (struct ubi_ec2_point_add_out *)calloc(1,sizeof(struct ubi_ec2_point_add_out));
    if((*out) == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (**out).point = (struct ubi_buffer *)calloc(1,sizeof(struct ubi_buffer));
    if((**out).point == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    octet_r = (octet *)calloc(1,sizeof(octet));
    (*octet_r).val = (char *)calloc(ECP2_FP256BN_LENGTH, sizeof(char));
    if((*octet_r).val == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    ECP2_FP256BN_toOctet(octet_r, R, false);
    (**out).point->buffer = (uint8_t *)(*octet_r).val;
    (**out).point->buffer_len = (size_t)(*octet_r).len;

cleanup:
    if(R != NULL){ free(R);}
    if(Q != NULL){ free(Q);}
    if(octet_q != NULL){ free(octet_q);}
    if(octet_r != NULL){ free(octet_r);}

    return ret;
}

int ubi_ec2_point_add(struct ubi_ec2_point_add_in *in, struct ubi_ec2_point_add_out **out)
{
    int ret = UBI_SUCCESS;
    switch ((*in).curve_type)
    {
    case BNP_256:
        ret = ubi_ec2_point_add_fp256(in, out);
        break;
    
    default:
        ret = UBI_NOT_IMPLEMENTED_ERROR;
        break;
    }
    return ret;
}

int free_ubi_ec2_point_add_out(struct ubi_ec2_point_add_out *out){
    if(out == NULL){
        return UBI_SUCCESS;
    }
    if((*out).point != NULL){
        if((*out).point->buffer != NULL){
            free((*out).point->buffer);
        }
        free((*out).point);
    }
    free(out);
    return UBI_SUCCESS;
}