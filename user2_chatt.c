#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <time.h>
#define MSGSZ 3000

/*
* Declare the message structure.
*/

typedef struct msgbuf {
	long    mtype;
	unsigned char    mtext[MSGSZ];
} message_buf;

static const unsigned char key[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

main()
{
	printf("===================================================\n");
	printf("   /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$\n");
	printf("  /$$__  $$ /$$__  $$| $$  | $$ /$$__  $$|__  $$__/\n");
	printf("    | $$  \__/| $$  \__/| $$  | $$| $$  \ $$   | $$   \n");
	printf(" |  $$$$$$ | $$      | $$$$$$$$| $$$$$$$$   | $$   \n");
	printf("  \ ____  $$| $$      | $$__  $$| $$__  $$   | $$   \n");
	printf("   /$$  \ $$| $$    $$| $$  | $$| $$  | $$   | $$   \n");
	printf(" |  $$$$$$/|  $$$$$$/| $$  | $$| $$  | $$   | $$   \n");
	printf("    \______/  \______/ |__/  |__/|__/  |__/   |__/   \n");
	printf("===================================================\n");
	int msqid;
	key_t idkey;
	AES_KEY encrypt_key,decrypt_key;
	unsigned char buf2[MSGSZ];
	unsigned char buf3[MSGSZ];
	message_buf  rbuf,sbuf;
	time_t  now;
	struct tm ts;
	char buf[80];
	size_t buf_length;
	/*
	* Get the message queue id for the
	* "name" 3200, which was created by
	* the server.
	*/
	idkey = 3200;

	if ((msqid = msgget(idkey, 0666)) < 0) {
		perror("msgget");
		exit(1);
	}


	while(1){

		/*Get current time*/
                time(&now);
                /*Format time*/
                ts = *localtime(&now);
                strftime(buf, sizeof(buf),"%H:%M:%S", &ts);

		if (msgrcv(msqid, &rbuf, MSGSZ, 1, 0) < 0) {
			perror("msgrcv");
			exit(1);
		}else   
			AES_set_decrypt_key(key,128,&decrypt_key);
			AES_decrypt(rbuf.mtext,buf2,&decrypt_key);
			strcpy(sbuf.mtext,buf2);
			printf("\n[%s][recv] User 1:%s",buf, sbuf.mtext);
		
		sbuf.mtype = 2;
		printf("\nYou Must Enter Message 'close' to close connection:");
		gets(&sbuf.mtext);
		
		if(strcmp(sbuf.mtext,"close")==0){
			strcpy(sbuf.mtext,"Connection closed by Other Process");
			buf_length = strlen(sbuf.mtext) + 1 ;
			if (msgsnd(msqid, &sbuf, buf_length, IPC_NOWAIT) < 0) {
				printf ("%d, %d, %s, %d\n", msqid, sbuf.mtype, sbuf.mtext, buf_length);
				perror("msgsnd");
				exit(1);
			}
			printf("\nClosing Connection");
			break;
		}
	
		buf_length = strlen(sbuf.mtext) + 1 ;
		if (msgsnd(msqid, &sbuf, buf_length, IPC_NOWAIT) < 0) {
			printf ("%d, %d, %s, %d\n", msqid, sbuf.mtype, sbuf.mtext, buf_length);
			perror("msgsnd");
			exit(1);
		}else
		       	AES_set_encrypt_key(key, 128, &encrypt_key);
			AES_encrypt(sbuf.mtext,buf3,&encrypt_key);	
			strcpy(sbuf.mtext,buf3);
			printf("\n[%s][sent] User 2:%s",buf, sbuf.mtext);
	

	}
	
	exit(0);
}
