#include <err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#include <keyvault_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
#define RSA_EXP 17 //generally 3, 17 or 65537

struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_KV_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}

void rsa_gen_keys_ca() {
	RSA *keypair = NULL;
	unsigned char *pub_key = NULL;
	BIGNUM *bne = NULL;
	unsigned long e = RSA_F4;
	int success = 0;

	bne = BN_new();
    success = BN_set_word(bne, e);
    if (!success) {
		errx(1, "\nrsa_gen_keys_ca failed at BN_set_word result.");
        goto free_all;
    }

	keypair = RSA_new();
	success = RSA_generate_key_ex(keypair, RSA_KEY_SIZE, bne, NULL);
    if (!success) {
		errx(1, "\nrsa_gen_keys_ca failed at RSA_generate_key_ex result.");
        goto free_all;
    }

	success = i2d_RSAPublicKey(keypair, &pub_key);
	if (success < 0) {
		errx(1, "\nrsa_gen_keys_ca failed at i2d_RSAPublicKey result.");
		goto free_all;
	}
	printf("==========RSA Public Key successfuly extracted: %s", pub_key);
	// BIO *priv_key = BIO_new(BIO_s_mem());
	// BIO *pub_key = BIO_new(BIO_s_mem());
	// PEM_write_bio_RSAPrivateKey(priv_key, keypair, NULL, NULL, 0, NULL, NULL);
	// PEM_write_bio_RSAPublicKey(pub_key, keypair);


	//TODO get the pub and priv parts in bytes format...
free_all:
	// BIO_free_all(pub_key);
    // BIO_free_all(priv_key);
    RSA_free(keypair);
    BN_free(bne);
}

void rsa_gen_keys(struct ta_attrs *ta) {
	TEEC_Result res;

	res = TEEC_InvokeCommand(&ta->sess, TA_KV_CMD_GENKEYS, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_KV_CMD_ENCRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was encrypted: %s\n", out);
}

void rsa_decrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA DECRYPT CA SIDE ============\n");
	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_KV_CMD_DECRYPT, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was decrypted: %s\n", (char *)op.params[1].tmpref.buffer);
}

int main(int argc, char *argv[])
{//TODO add a good print function (fflush)
	struct ta_attrs ta;
	// char clear[RSA_MAX_PLAIN_LEN_1024];
	// char ciph[RSA_CIPHER_LEN_1024];
	rsa_gen_keys_ca();
	
	prepare_ta_session(&ta);
	//printf("\nType something to be encrypted and decrypted in the TA:\n");
	//fflush(stdin); //setbuf(stdin, NULL);
	//fgets(clear, sizeof(clear), stdin);

	rsa_gen_keys(&ta);
	//rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024);
	//rsa_decrypt(&ta, ciph, RSA_CIPHER_LEN_1024, clear, RSA_MAX_PLAIN_LEN_1024);

	//
	
	terminate_tee_session(&ta);
	return 0;
}
