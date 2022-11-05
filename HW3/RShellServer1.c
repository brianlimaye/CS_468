/* 

  SimpleRShellServer.c

  Created by Xinyuan Wang for CS 468

  All rights reserved.

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

#define DEBUG

#define TIMEOUT 60

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
#define RSHELL_RESULT '6'

struct tcp_message {

	char message_type;
	short payload_len;
	char id[ID_MAX_SIZE];
	char mr;
	char * payload;
};

typedef struct auth_user {
    char                *user;
    time_t              timestamp;
    struct auth_user    *next;
} AUTH_USER;

AUTH_USER * cache = NULL;

void insert_auth(char *user) {

    time_t now = time(NULL);
    AUTH_USER *new = malloc(sizeof(AUTH_USER));
    if (! new) {
        perror("malloc");
        exit(1);
    }
    new->user = strdup(user);
    if (! new->user) {
        perror("strdup");
        exit(1);
    }
    printf("debug insert: now = %ld\n", now);
    new->timestamp = now;
    new->next = cache;
    cache = new;
}

int is_auth(char *user) {

    int auth = 0;
    AUTH_USER *expired;
    AUTH_USER **p;
    time_t now, delta;
    now = time(NULL);
    p = &cache;
    while (*p) {
        delta = now - (*p)->timestamp;
        if (delta > TIMEOUT) {
            // remove items older than TIMEOUT seconds
            expired = (*p);
            (*p) = (*p)->next; // point past removed item
            printf("debug expired: %s %ld\n", expired->user, delta);
            free(expired->user);
            free(expired);
            continue;
        }
        // otherwise item is younger than TIMEOUT seconds
        if (!strcmp(user, (*p)->user)) {
            printf("debug found: %s %ld\n", user, delta);
            auth = 1;
        }
        if (*p) {
            p = &((*p)->next);
        }
    }
    return auth;
}

void dump_auth() {
    AUTH_USER *p;
    printf("cache:\n");
    for (p = cache ; p ; p = p->next) {
        printf("user = %s, timestamp = %ld\n", p->user, p->timestamp);
    }
}

char *trim(char *str)
{
    char *start = str;
    char *end = str + strlen(str);

    while(*start && isspace(*start))
        start++;

    while(end > start && isspace(*(end - 1)))
        end--;

    *end = '\0';
    return start;
}

int parse_line(char *line, char **key, char **value)
{
    char *ptr = strchr(line, ';');
    if (ptr == NULL)
        return -1;

    *ptr++ = '\0';
    *key = trim(line);
    *value = trim(ptr);

    return 0;
}

char * get_password(char * filename, char * searchKey)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *key, *value, *ret=NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf ("Cannot open file \n");
        return NULL;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if (parse_line(line, &key, &value))
            continue;

        if (strcmp(key, searchKey) == 0) {
            ret = strdup(value);
            goto done;
        }
    }

    done:
    free(line);
    fclose(fp);

    return ret;
}

int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
}

int 
serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}

int 
serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void 
usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void 
errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it 
	can not handle properly:

	cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock)
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;

#ifdef DEBUG
	printf("***** RemoteShellD(sock=%d) called\n", sock);
#endif

	while ((cc = read(sock, cmd, BUFSZ)) > 0)	/* received something */
	{	
		
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("***** cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */

		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		pclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
}

void execute_command(char * command, char * id, int socket) {

	int len;
	int pay_len = 0;
	struct tcp_message R_SHELL_RESULT;
	FILE * output;
	char buffer[1024];

	memset(buffer, 0, 1024);

	printf("Executing command...\n");

	output = popen(command, "r");
	//strcat(command, "2>&1");

	if(output == NULL) {

	   printf("Cannot open file for executing command!\n");
	   exit(1);
	}

	printf("Command executed!\n");

	R_SHELL_RESULT.message_type = RSHELL_RESULT;
        memcpy(R_SHELL_RESULT.id, id, ID_MAX_SIZE - 1);
        R_SHELL_RESULT.id[strlen(id)] = '\0';
	R_SHELL_RESULT.mr = '1';

	while(fgets(buffer, 1024, output) != NULL) {

		int buff_len = strlen(buffer);

		printf("%s", buffer);

		R_SHELL_RESULT.payload_len = buff_len;
		R_SHELL_RESULT.payload = buffer;

		write_to_socket(R_SHELL_RESULT, socket);

		memset(buffer, 0, 1024);

		//printf("RSHELL_RESULT Successfully written to socket.\n"); 
	
		sleep(0.5);
	}

	R_SHELL_RESULT.payload_len = 0;
	R_SHELL_RESULT.mr = '0';
	R_SHELL_RESULT.payload = NULL;

	write_to_socket(R_SHELL_RESULT, socket);

	pclose(output);
}


void write_to_socket(struct tcp_message message, int socket) {

	/*if(*/write(socket, &(message.message_type), TYPE_MAX_SIZE); /*!= TYPE_MAX_SIZE) {

			fprintf(stderr, "Cannot write TCP message type to socket!");
			close(socket);
			return;
	}*/

	printf("Server wrote message_type: %c\n", message.message_type);

	if(write(socket, &(message.payload_len), PL_MAX_SIZE) != PL_MAX_SIZE) {

		  fprintf(stderr, "Cannot write TCP payload length to socket!");
		  close(socket);
		  return;
	}

	printf("Server wrote payload_len: %hu\n", message.payload_len);

	if(write(socket, message.id, ID_MAX_SIZE) != ID_MAX_SIZE) {

                fprintf(stderr, "Cannot write TCP id to socket!");
                close(socket);
                return message;
        }

	printf("Server wrote id: %s\n", message.id);

	if(write(socket, &(message.mr), TYPE_MAX_SIZE) != TYPE_MAX_SIZE) {

		fprintf(stderr, "Cannot write TCP mr to socket!\n");
		close(socket);
		return message;
	}

	printf("Server wrote mr: %c\n", message.mr);

	if(message.payload_len > 0) {

		write(socket, message.payload, message.payload_len);
		printf("Server wrote payload: %s\n", message.payload);
	}
}

struct tcp_message read_from_socket(int socket) {

	struct tcp_message message;

	if(recv(socket, &(message.message_type), TYPE_MAX_SIZE, 0) != TYPE_MAX_SIZE) {

		printf("Cannot read TCP message type from socket!");
		close(socket);
		return message;
	}

	//printf("message type: %c\n", message.message_type);

	if(recv(socket, &(message.payload_len), PL_MAX_SIZE, 0) != PL_MAX_SIZE) {

		fprintf(stderr, "Cannot read TCP payload length to socket!");
		close(socket);
		return message;
	}

	//printf("message p_size: %hu\n", message.payload_len);

	if(recv(socket, message.id, ID_MAX_SIZE, 0) != ID_MAX_SIZE) {

                fprintf(stderr, "Cannot read TCP id from socket!");
                close(socket);
                return message;
        }
	//printf("message id: %s\n", message.id);
	
	message.payload = malloc((message.payload_len + 1) * sizeof(char));
	
	recv(socket, message.payload, message.payload_len, 0);
	message.payload[message.payload_len] = '\0';
	//printf("message payload: %s\n", message.payload);

	return message;
}

/*------------------------------------------------------------------------
 * main - Concurrent TCP server 
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int	 msock;			/* master server socket		*/
	int	 ssock;			/* slave server socket		*/
	int  portN;			/* port number to listen */
	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */
	struct tcp_message message = {.message_type = '\0',
																.payload_len = 0,
																.id = '\0',
																.payload = NULL };
	char * password_file;
	int  prefixL, r;

	if (argc==3) {

		portN = atoi(argv[1]);
		password_file = argv[2];
	}
	else usage(argv[0]);

	msock = serverTCPsock(portN, 5);

	(void) signal(SIGCHLD, reaper);

	while (1) 
	{
		fromAddrLen = sizeof(fromAddr);
		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}

		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);
				
				if((message = read_from_socket(ssock)).message_type > '0') {
						printf("Server Recieved Client Req\n");

				
						if(!is_auth(message.id)) {

								if(message.message_type == RSHELL_REQ) {
										
										printf("Server received RSHELL_REQ\n");
	    							 									
										struct tcp_message AUTH_REQUEST;
										AUTH_REQUEST.message_type = AUTH_REQ;
			
										AUTH_REQUEST.payload_len = 0;
										memcpy(AUTH_REQUEST.id, message.id, ID_MAX_SIZE - 1);
										AUTH_REQUEST.id[strlen(message.id)] = '\0';

AUTH_REQUEST.mr = '0';
										AUTH_REQUEST.payload = NULL;

										write_to_socket(AUTH_REQUEST, ssock);

										struct tcp_message AUTH_RESPONSE = read_from_socket(ssock);
							          
										if(AUTH_RESPONSE.message_type == AUTH_RESP) {

											printf("Server received AUTH_RESP\n");

											struct tcp_message AUTH_RESULT;

											char * sha1_password = get_password(password_file, message.id);

											if((sha1_password != NULL) && (strncmp(sha1_password, AUTH_RESPONSE.payload, 40) == 0)) {

												insert_auth(message.id);
												AUTH_RESULT.message_type = AUTH_SUCCESS;
											}
											else {
												AUTH_RESULT.message_type = AUTH_FAIL;
											}

											memcpy(AUTH_RESULT.id, message.id, ID_MAX_SIZE - 1);
											AUTH_RESULT.id[strlen(message.id)] = '\0';
											AUTH_RESULT.payload_len = 0;
					
	AUTH_RESULT.mr = '0';		
											AUTH_RESULT.payload = NULL;

											free(sha1_password);
											write_to_socket(AUTH_RESULT, ssock);

											if(AUTH_RESULT.message_type == AUTH_FAIL) {
		break;
	}
											execute_command(message.payload, message.id, ssock);		
	 
								}
						}
				}
				}
				
				close(ssock);
				exit(r);
				

			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}

