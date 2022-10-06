/*
 * Brian Limaye
 * G01260841
 * HW #2 Q4b
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/*
 * Parses the key file name from the command line args.
 */
char * get_key_filename(char * argv[]) {

	if((strcmp(argv[1], "-k") != 0) || (strcmp(argv[3], "-v") != 0)) {
		
		fprintf(stderr, "Incorrect format for key file name.\n");
		exit(1);
	}

	return argv[2];
}

/*
 * Parses the iv file name from the command line args.
 */
char * get_iv_filename(char * argv[]) {

	if((strcmp(argv[3], "-v") != 0) || (strcmp(argv[5], "-i") != 0)) {
		
		fprintf(stderr, "Incorrect format for iv file name.\n");
		exit(1);
	}

	return argv[4];
}

/*
 * Parses the input file name from the command line args.
 */
char * get_input_filename(char * argv[]) {

	if((strcmp(argv[5], "-i") != 0) || (strcmp(argv[7], "-o"))) {
		
		fprintf(stderr, "Incorrect format for input file name.\n");
		exit(1);
	}

	return argv[6];
}

/*
 * Parses the output file name from the command line args.
 */
char * get_output_filename(char * argv[]) {

	if(strcmp(argv[7], "-o") != 0) {

		fprintf(stderr, "Incorrect format for output file name.\n");
		exit(1);
	}

	return argv[8];
}

/*
 * Parses a given file and returns its contents in a buffer.
 */
char * parse_file(char * file, int * len, int mode) {
	
	FILE * fp;

	/*
	 * Determines which type of file should be read, whether it's a binary or ascii file.
	 */
	char * perm = (mode == 1) ? "rb" : "r";

	fp = fopen(file, perm);

	if(fp == NULL) {

		fprintf(stderr, "Cannot open file.\n");
		exit(1);
	}

	/*
	 * Gets the length/size of the file.
	 */
	fseek(fp, 0, SEEK_END);
	*len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char * file_contents = (char *) malloc((*len) * sizeof(char));

	if(file_contents == NULL) {

		fprintf(stderr, "Cannot allocate memory for file contents!\n");
		exit(1);
	}
	
	fread(file_contents, *len, 1, fp);

	/*
	 * Null terminates the input buffer only if the contents are ascii.
	 */
	if(!mode) {
		file_contents[*len - 1] = '\0';
	}

	fclose(fp);

	return file_contents;
}

/*
 * Performs AES256_CBC decryption on a given ciphertext, given a key and iv.
 */
int do_AES_decrypt(char * output_filename, char * enc, int enc_len, unsigned char * key, unsigned char * iv) {

	int output_len = 0;
	int final_len = 0;

	/*
	 * Output buffer, where the decrypted plaintext will be stored.
	 */
	unsigned char output_buffer[enc_len + EVP_MAX_BLOCK_LENGTH];
	
	EVP_CIPHER_CTX * ctx = NULL;

	ctx = EVP_CIPHER_CTX_new();
	
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	/*
	 * Decrypts most of the blocks of the plaintext.
	 */
	if(EVP_DecryptUpdate(ctx, output_buffer, &output_len, enc, enc_len) == 0) {	       		
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	/*
	 * Decrypts any potential final block.
	 */
	EVP_DecryptFinal_ex(ctx, output_buffer + output_len, &final_len);

	output_len = output_len + final_len;

	/*
	 * Writes the decrypted text (plaintext) into the output file.
	 */
	FILE * output = fopen(output_filename, "w");

	if(output == NULL) {

		fprintf(stderr, "Cannot open output file for writing...\n");
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	fwrite(output_buffer, 1, output_len, output);
	fclose(output);

	EVP_CIPHER_CTX_free(ctx);

	return 1;
}

int main(int argc, char * argv[]) {
	
	if(argc != 9) {
		fprintf(stderr, "Incorrect # of arguments.\n");
		exit(1);
	}

	int input_len;
	int key_len;
	int iv_len;

	char * output_filename = get_output_filename(argv);
	char * key = parse_file(get_key_filename(argv), &key_len, 0);
	
	if(strlen(key) != 64) {

		fprintf(stderr, "Key is not 32 bytes...\n");
		free(key);
		exit(1);
	}

	char * iv = parse_file(get_iv_filename(argv), &iv_len, 0);

	if(strlen(iv) != 32) {

		fprintf(stderr, "Iv is not 16 bytes...\n");
		free(key);
		free(iv);
		exit(1);
	}

	char * input_cipher = parse_file(get_input_filename(argv), &input_len, 1);
		
	if(input_len < 2) {

		fprintf(stderr, "Plaintext file is empty!\n");
		free(key);
		free(iv);
		free(input_cipher);
		exit(1);
	}

	do_AES_decrypt(output_filename, input_cipher, input_len, (unsigned char *) key, (unsigned char *) iv);

	free(key);
	free(iv);
	free(input_cipher);

	return 1;
}
