#include <stdlib.h>
#include <stdint.h>

#include <ecp2_FP256BN.h>
#include <ecp_FP256BN.h>
#include <fp12_FP256BN.h>
#include <pair_FP256BN.h>


#include <ubi_crypt/pairings.h>
#include <ubi_common/errors.h>
#include <ubi_common/structs.h>
#include <ubi_common/macros.h>


int ubi_verify_bbs_fp256_pairings(struct ubi_verify_bbs_pairings_in *in, struct ubi_verify_bbs_pairings_out *out);

int ubi_verify_bbs_fp256_pairings(struct ubi_verify_bbs_pairings_in *in, struct ubi_verify_bbs_pairings_out *out){
    int ret = UBI_SUCCESS;
    ECP2_FP256BN *core_point2_a = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    ECP_FP256BN *core_point_b = (ECP_FP256BN *)calloc(1,sizeof(ECP_FP256BN));
    ECP2_FP256BN *core_point2_c = (ECP2_FP256BN *)calloc(1,sizeof(ECP2_FP256BN));
    ECP_FP256BN *core_point_d = (ECP_FP256BN *)calloc(1,sizeof(ECP_FP256BN));
    FP12_FP256BN *lhs = NULL;
    FP12_FP256BN *rhs = NULL;
    if(core_point2_a == NULL || core_point_b == NULL || core_point2_c == NULL || core_point_d == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    
    octet *octet_point2_a = (octet *)calloc(1,sizeof(octet));
    octet *octet_point_b = (octet *)calloc(1,sizeof(octet));
    octet *octet_point2_c = (octet *)calloc(1,sizeof(octet));
    octet *octet_point_d = (octet *)calloc(1,sizeof(octet));
    if(octet_point2_a == NULL || octet_point_b == NULL || octet_point2_c == NULL || octet_point_d == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    (*octet_point2_a).val = (char *)(*in).point2_a->buffer;   
    (*octet_point2_a).len = (int)(*in).point2_a->buffer_len;
    (*octet_point_b).val = (char *)(*in).point_b->buffer;
    (*octet_point_b).len = (int)(*in).point_b->buffer_len;
    (*octet_point2_c).val = (char *)(*in).point2_c->buffer;
    (*octet_point2_c).len = (int)(*in).point2_c->buffer_len;
    (*octet_point_d).val = (char *)(*in).point_d->buffer;
    (*octet_point_d).len = (int)(*in).point_d->buffer_len;
    if(!ECP2_FP256BN_fromOctet(core_point2_a, octet_point2_a)){
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if(!ECP_FP256BN_fromOctet(core_point_b, octet_point_b)){
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if(!ECP2_FP256BN_fromOctet(core_point2_c, octet_point2_c)){
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    if(!ECP_FP256BN_fromOctet(core_point_d, octet_point_d)){
        ret = UBI_READ_BIN_ERROR;
        goto cleanup;
    }
    lhs = (FP12_FP256BN *)calloc(1,sizeof(FP12_FP256BN));
    rhs = (FP12_FP256BN *)calloc(1,sizeof(FP12_FP256BN));

    if(lhs == NULL || rhs == NULL){
        ret = UBI_MEM_ERROR;
        goto cleanup;
    }
    
    PAIR_FP256BN_ate(lhs, core_point2_a, core_point_b);
    PAIR_FP256BN_fexp(lhs);

    PAIR_FP256BN_ate(rhs, core_point2_c, core_point_d);
    PAIR_FP256BN_fexp(rhs);

    if (FP12_FP256BN_equals(lhs, rhs) == 0) {
        ret  = UBI_PAIRING_VERIFICATION_FAILED;
        goto cleanup;
    }
    

cleanup:
    if(core_point2_a != NULL) {free(core_point2_a); core_point2_a = NULL;}
    if(core_point_b != NULL) {free(core_point_b); core_point_b = NULL;}
    if(core_point2_c != NULL) {free(core_point2_c); core_point2_c = NULL;}
    if(core_point_d != NULL) {free(core_point_d); core_point_d = NULL;}
    if(octet_point2_a != NULL) {free(octet_point2_a); octet_point2_a = NULL;}
    if(octet_point_b != NULL) {free(octet_point_b); octet_point_b = NULL;}
    if(octet_point2_c != NULL) {free(octet_point2_c); octet_point2_c = NULL;}
    if(octet_point_d != NULL) {free(octet_point_d); octet_point_d = NULL;}
    if(lhs != NULL) {free(lhs); lhs = NULL;}
    if(rhs != NULL) {free(rhs); rhs = NULL;}
    (*out).pairing_status = ret;
    return ret;
}


int ubi_verify_bbs_pairings(struct ubi_verify_bbs_pairings_in *in, struct ubi_verify_bbs_pairings_out *out){
    int ret = UBI_SUCCESS;
    switch ((*in).curve_type)
    {
    case BNP_256:
        ubi_verify_bbs_fp256_pairings(in, out);
        break;
    
    default:
        ret = UBI_NOT_IMPLEMENTED_ERROR;
        break;
    }
    

    return ret;

}