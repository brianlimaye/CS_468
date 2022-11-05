/* 

  SimpleRShellClient.c

  Created by Xinyuan Wang for CS 468
 
  All rights reserved.
*/

#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>

//#define DEBUG

#define TYPE_MAX_SIZE			1
#define PL_MAX_SIZE				2
#define ID_MAX_SIZE				16
#define	PASS_MAX_SIZE			40

#define PAYLOAD_MAX_SIZE  65535


#define RSHELL_REQ		'1'
#define AUTH_REQ 			'2'
#define AUTH_RESP			'3'
#define AUTH_SUCCESS	'4'
#define AUTH_FAIL			'5'
#define RSHELL_RESULT 			'6'

struct tcp_message {

	char message_type;
	short payload_len;
	char id[ID_MAX_SIZE];
	char mr;
	char * payload;
};

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6 
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1) 
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}
int 
clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}


int 
clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}

#define	LINELEN		128
#define resultSz	4096

void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin)) 
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{
#ifdef DEBUG
			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, outchars, buf);
#endif /* DEBUG */
			close(sock);
			return -1;
		}
#ifdef DEBUG
		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, buf);
#endif /* DEBUG */

		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;	
			fputs(result, stdout);			
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}

void write_to_socket(struct tcp_message message, int socket) {

	if(write(socket, &(message.message_type), TYPE_MAX_SIZE) != TYPE_MAX_SIZE) {

			fprintf(stderr, "Cannot write TCP message type to socket!");
			close(socket);
			return;
	}
	
	if(write(socket, &(message.payload_len), PL_MAX_SIZE) != PL_MAX_SIZE) {

		 fprintf(stderr, "Cannot write TCP payload length to socket!");
		 close(socket);
		 return;
	}

	printf("p_len: %hu\n", message.payload_len);

	if(write(socket, message.id, ID_MAX_SIZE) != ID_MAX_SIZE) {

		fprintf(stderr, "Cannot write TCP message id to socket!");
		close(socket);
		return;
	}

	printf("id: %s\n", message.id);
	
	write(socket, message.payload, message.payload_len);

	printf("payload: %s\n", message.payload);
}

struct tcp_message read_from_socket(int socket) {

	struct tcp_message message; 

	if(recv(socket, &(message.message_type), TYPE_MAX_SIZE, 0) != TYPE_MAX_SIZE) {

		fprintf(stderr, "Cannot read TCP message type from socket!");
		close(socket);
		return message;
	}

	if(recv(socket, &(message.payload_len), PL_MAX_SIZE, 0) != PL_MAX_SIZE) {

		fprintf(stderr, "Cannot read TCP payload length to socket!");
		close(socket);
		return message;
	}

	if(recv(socket, message.id, ID_MAX_SIZE, 0) != ID_MAX_SIZE) {

		fprintf(stderr, "Cannot read TCP id from socket!");
		close(socket);
		return message;
	}

	if(recv(socket, &(message.mr), TYPE_MAX_SIZE, 0) != TYPE_MAX_SIZE) {

		fprintf(stderr, "Cannot read TCP mr from socket!\n");
		close(socket);
		return message;
	}


	if(message.payload_len > 0) {
		
		message.payload = malloc((message.payload_len + 1) * sizeof(char));
		recv(socket, message.payload, message.payload_len, 0);
		message.payload[message.payload_len] = '\0';
	}
	else {
		message.payload = NULL;
	}

	return message;
}

/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int i;
	char *destination;
	int  portN;
	char * id;
	char * tmp_pass;

	unsigned char hex_pass[SHA_DIGEST_LENGTH];
	char byte_pass[SHA_DIGEST_LENGTH * 2 + 1];

	memset(hex_pass, 0x0, SHA_DIGEST_LENGTH);
	memset(byte_pass, 0x0, SHA_DIGEST_LENGTH * 2);

	if (argc==5)
	{ 
	  destination = argv[1];
	  portN = atoi(argv[2]);
	  id = argv[3];
	  tmp_pass = argv[4];
	}
	else usage(argv[0]);

	SHA1((unsigned char *) tmp_pass, strlen(tmp_pass), hex_pass);
	
	for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(&(byte_pass[i * 2]), "%02x", hex_pass[i]);
	}

	byte_pass[SHA_DIGEST_LENGTH * 2] = '\0';

	//printf("Password in RAW BYTES: %s\n", byte_pass);
	//printf("Password (SHA1) is: %s\n", byte_pass);
		
	
	int socket = clientTCPsock(destination, portN);
	
	if(socket < 0) {

		fprintf(stderr, "Could not connect to socket...\n");
		exit(1);
	}

	char cmd[8192];
	cmd[0] = '\0';
	struct tcp_message R_SHELL_REQ;
	struct tcp_message AUTH_RESPONSE;
	
	while(fgets(cmd, 8192, stdin)) {
		
		if(strlen(cmd) > 1) { 
			
			cmd[strlen(cmd) - 1] = '\0';
			R_SHELL_REQ.message_type = RSHELL_REQ;
			R_SHELL_REQ.payload_len = strlen(cmd);
			memcpy(R_SHELL_REQ.id, id, ID_MAX_SIZE - 1);
			R_SHELL_REQ.id[strlen(id)] = '\0';
			R_SHELL_REQ.payload = cmd;

			write_to_socket(R_SHELL_REQ, socket);
			printf("Client Sent RSHELL_REQ\n"); 
			
		
			struct tcp_message MSG_RESPONSE = read_from_socket(socket);
			printf("AUTH_REQ message type: %c\n", MSG_RESPONSE.message_type);
			printf("AUTH_REQ payload_len: %hu\n", MSG_RESPONSE.payload_len);
			printf("AUTH_REQ id: %s\n", MSG_RESPONSE.id);
			
			
			
			if(MSG_RESPONSE.message_type == AUTH_REQ) {
				
				printf("Client Received AUTH_REQ\n");
				
				AUTH_RESPONSE.message_type = AUTH_RESP;
				AUTH_RESPONSE.payload_len = strlen(byte_pass);
				memcpy(AUTH_RESPONSE.id, id, ID_MAX_SIZE - 1);
				AUTH_RESPONSE.id[strlen(id)] = '\0';
				AUTH_RESPONSE.payload = byte_pass;

				write_to_socket(AUTH_RESPONSE, socket);
				printf("Client sent AUTH_RESPONSE\n");

					
				struct tcp_message MSG_RESPONSE2 = read_from_socket(socket);

				
				if(MSG_RESPONSE2.message_type == AUTH_SUCCESS) {

					printf("Received AUTH_SUCCESS\n");
					struct tcp_message MSG_RESPONSE3 = read_from_socket(socket);

					printf("Command Output: ");
					if(MSG_RESPONSE3.message_type == RSHELL_RESULT) {
						
						//printf("Received RSHELL_RESULT\n");
						do {
						
							if(MSG_RESPONSE3.payload_len > 0) {								
								printf("%s", MSG_RESPONSE3.payload);
								MSG_RESPONSE3 = read_from_socket(socket);							 }
						}
						while(MSG_RESPONSE3.mr == '1');
					}
				}

				if(MSG_RESPONSE2.message_type == AUTH_FAIL) {

					fprintf(stderr, "Authentication failed...");
					close(socket);
					exit(1);
				}
			}

			/*else if(MSG_RESPONSE.message_type == RSHELL_RESULT) {

				struct tcp_message MSG_RESPONSE4 = read_from_socket(socket);

                                if(MSG_RESPONSE4.message_type == RSHELL_RESULT) {

                                	while(MSG_RESPONSE4.payload[0] > 0) {

                                        	MSG_RESPONSE4.payload++;
                                                printf(MSG_RESPONSE4.payload);
                                                MSG_RESPONSE4 = read_from_socket(socket);
                                        }
                                }

			}*/
		}
	
	}


	exit(0);
}

