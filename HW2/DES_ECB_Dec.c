/*
 * Brian Limaye
 * G01260841
 * HW #2 Q4a
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/*
 * Parses the key file name from the command line args.
 */
char * get_key_filename(char ** argv) {

	if((strcmp(argv[1], "-k") != 0) || (strcmp(argv[3], "-i") != 0)) {
		
		fprintf(stderr, "Incorrect format for key.\n");
		exit(1);
	}

	return argv[2];
}

/*
 * Parses the input file name from the command line args.
 */
char * get_input_filename(char ** argv) {

	if((strcmp(argv[3], "-i") != 0) || (strcmp(argv[5], "-o"))) {
		
		fprintf(stderr, "Incorrect format for input file.\n");
		exit(1);
	}

	return argv[4];
}

/*
 * Parses the output file name from the command line args.
 */
char * get_output_filename(char ** argv) {

	if(strcmp(argv[5], "-o") != 0) {

		fprintf(stderr, "Incorrect format for output file.\n");
		exit(1);
	}

	return argv[6];
}

/*
 * Parses a given file and returns its contents in a buffer.
 */
char * parse_file(char * file, int * len, int mode) {
	
	FILE * fp;
	/*
	 * Determines whether the file needs to be null-terminated or not, based on if the data is binary or not.
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
	 * Null-terminates the input buffer only if the data is not binary.
	 */
	if(!mode) {
		file_contents[*len - 1] = '\0';
	}

	fclose(fp);

	return file_contents;
}

/*
 * Performs the DES decryption on a given input ciphertext.
 */
int do_DES_decrypt(char * output_filename, char * enc, int enc_len, unsigned char * key) {
	
	int output_len;
	int final_len;

	/*
	 * Output buffer, where the decrypted text will be stored.
	 */
	unsigned char output_buffer[enc_len + EVP_MAX_BLOCK_LENGTH];
	
	EVP_CIPHER_CTX * ctx = NULL;

	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL);

	/*
	 * Decrypts most of the blocks, potentially leaving the last for EVP_DecryptFinal_ex
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
	 * Writes the output buffer containing the decrypted text into the output file.
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

int main(int argc, char ** argv) {

	if(argc != 7) {
		fprintf(stderr, "Incorrect # of arguments.\n");
		exit(1);
	}

	int input_len;
	int key_len;

	char * output_filename = get_output_filename(argv);
	
	char * key = parse_file(get_key_filename(argv), &key_len, 0);

	if(strlen(key) != 16) {

		fprintf(stderr, "Key is not 8 bytes...\n");
		free(key);
		exit(1);
	}
	
	
	char * input_cipher = parse_file(get_input_filename(argv), &input_len, 1);

	
	if(input_len < 2) {

		fprintf(stderr, "Ciphertext file is empty!\n");
		free(key);
		free(input_cipher);
		exit(1);
	}

	do_DES_decrypt(output_filename, input_cipher, input_len,  key);

	free(key);
	free(input_cipher);
	
	return 1;
}
