/*
  Original code credits to:
  retro98se @ gmail.com with modifications by dragonslair @ gmail.com

  See README.orig for previous changes
*/ 
/*
  This program is a re-re-implementation of the telnet console enabler utility
  for use with Netgear wireless routers.
  
  The original Netgear Windows binary version of this tool is available here:
  http://www.netgear.co.kr/Support/Product/FileInfo.asp?IDXNo=155
  
  Per DMCA 17 U.S.C. §1201(f)(1)-(2), the original Netgear executable was
  reverse engineered to enable interoperability with other operating systems
  not supported by the original windows-only tool (MacOS, Linux, etc).

    Netgear Router - Console Telnet Enable Utility 
    Release 0.1 : 25th June 2006
    Copyright (C) 2006, yoshac @ member.fsf.org

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


  The RSA MD5 and Blowfish implementations are provided under LGPL from
  http://www.opentom.org/Mkttimage 
*/

#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// -lcrypto
#include <openssl/sha.h>

#include "md5.h"
#include "blowfish.h"

#define PORT 23
#define SECRET_KEY_PART "AMBIT_TELNET_ENABLE+"
#define SHA_256_STR_LEN SHA256_DIGEST_LENGTH*2
#define MD5_LEN             0x10
#define MAC_ADDR_STR_LEN    12
#define MAX_USERNAME_LEN    15
#define MAX_PWD_LEN         0x40


__attribute__((packed))
struct payload {
    char signature[0x10];
    char mac[0x10];
    char username[0x10];
    char password_hash[0x41];
    char reserved[0x10];
};

static char *sha256_string(const char *string) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *password_hash = malloc(SHA_256_STR_LEN + 1);
    int i = 0;
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(password_hash + (i * 2), "%02x", hash[i]);
    }

    password_hash[64] = 0;

    return password_hash;
}

static int send_payload(const char *host, in_port_t port, char *payload,
        size_t payload_len) { 
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(host);

    sendto(sockfd, payload, payload_len, MSG_CONFIRM,
            (const struct sockaddr*)&servaddr, sizeof(servaddr));
    printf("Sent telnet enable packet\n");

    close(sockfd);
    return 0;
}

static size_t blowfish_out_len(size_t input_len) {
    int mod_val = input_len % 8;

    if (mod_val != 0)
        return input_len + 8 - mod_val;
    else
        return input_len;
}

static ssize_t EncodeString(char *input, char **crypted_buf, int lSize,
        char *key, size_t key_len) {
    ssize_t count = -1;
    ssize_t out_len;
    int i;
    char *crypt_tmp = NULL;
    BLOWFISH_CTX ctx;

    // Create a buffer long enough to hold the blowfish output
    out_len = blowfish_out_len(lSize);
    *crypted_buf = malloc(out_len);
    if (*crypted_buf == NULL) {
        fprintf(stderr, "Failed to allocate memory for encrypted buffer\n");
        goto out;
    }
    crypt_tmp = *crypted_buf;


    Blowfish_Init(&ctx, key, key_len);

    count = 0;
    while(count < out_len) {
        unsigned int xl=0;
        unsigned int xr=0;

        for (i=3; i>=0; i--) {
            xl = (xl << 8) | (*(input+i) & 0xff);
            xr = (xr << 8) | (*(input+i+4) & 0xff);
        }

        Blowfish_Encrypt(&ctx, &xl, &xr);

        for (i=0; i<4; i++) {
            *(crypt_tmp+i) = xl & 0xff;
            xl >>= 8;
            *(crypt_tmp+i+4) = xr & 0xff;
            xr >>= 8;
        }

        input += 8;
        crypt_tmp += 8;
        count += 8;
    }

out:
    return count;
}

static void fill_payload(const char *rhost_mac_addr, const char *username,
        const char *password, struct payload *payload) {
    MD5_CTX MD;
    char md5_key[MD5_LEN];

    memset(payload, 0, sizeof(*payload));

    strncpy(payload->mac, rhost_mac_addr, sizeof(payload->mac));
    strncpy(payload->username, username, sizeof(payload->username));

    char *password_hash = sha256_string(password);
    strncpy(payload->password_hash, password_hash, sizeof(payload->password_hash));

    MD5Init(&MD);
    MD5Update(&MD, payload->mac, sizeof(payload->mac));
    MD5Update(&MD, payload->username, sizeof(payload->username));
    MD5Update(&MD, password_hash, SHA_256_STR_LEN);
    MD5Update(&MD, payload->reserved, sizeof(payload->reserved));
    MD5Final(md5_key, &MD);

    memcpy(payload->signature, md5_key, 0x10);

    free(password_hash);
    return;
}

static ssize_t generate_crypted_payload(struct payload *payload, char **crypted_payload) {
    ssize_t crypted_payload_len = -1;
    // TODO: fix buffer length
    char secret_key[sizeof(SECRET_KEY_PART)+SHA_256_STR_LEN+1] = SECRET_KEY_PART;

    // Generate the secret key
    memcpy(secret_key+sizeof(SECRET_KEY_PART)-1, payload->password_hash, SHA_256_STR_LEN);

    // The password must be MD5 hashed to 0x41 bytes, but the encoding requires a size of 0x80.
    // A password buffer of 0x41 means that the actual payload struct would be 0x81 in length.
    // Something seems off here -- It could be a weird Netgear implementation
    crypted_payload_len = EncodeString((char*)payload, crypted_payload,
            sizeof(*payload)-1, secret_key, strlen(secret_key));
    if (crypted_payload_len == -1) {
        fprintf(stderr, "Failed to encrypt payload\n");
        goto out;
    }

out:
    return crypted_payload_len;
}

static int enable_telnet(const char *rhost, const char *rhost_mac_addr,
        const char *username, const char *password) {
    int status = -1;
    struct payload payload = {};
    char *crypted_payload = NULL;
    ssize_t crypted_payload_len = -1;

    fill_payload(rhost_mac_addr, username, password, &payload);

    crypted_payload_len = generate_crypted_payload(&payload, &crypted_payload);
    if (crypted_payload_len == -1) {
        fprintf(stderr, "Failed to generated encrypted payload\n");
        goto out;
    }

    if (send_payload(rhost, PORT, crypted_payload, crypted_payload_len) != 0) {
        fprintf(stderr, "Failed to send payload\n");
        goto out;
    }

    status = 0;
out:
    free(crypted_payload);
    return status;
}

static void usage(char * progname) {
    fprintf(stderr, "Netgear telnetenable\n");
    fprintf(stderr, "Usage: %s <host ip> <host mac> <user name> <password>\n", progname);
    exit(1);
}

int main(int argc, char * argv[]) {
    int status = 1;
    int datasize;
    int i;

    if (argc != 5) {
        usage(argv[0]);
    }

    if (strlen(argv[2]) != MAC_ADDR_STR_LEN) {
        fprintf(stderr, "MAC address length must be %d\n", MAC_ADDR_STR_LEN);
        goto out;
    }

    for( i=0; i<MAC_ADDR_STR_LEN; i++) {
        if ( !isxdigit(argv[2][i]) ) {
            fprintf( stderr, "Invalid characters in MAC address\n" );
            goto out;
        }
    }

    if (strlen(argv[3]) > MAX_USERNAME_LEN) {
        fprintf(stderr, "Username too long\n");
        goto out;
    }

    if (strlen(argv[4]) > MAX_PWD_LEN) {
        fprintf(stderr, "Password too long\n");
        goto out;
    }

    if (enable_telnet(argv[1], argv[2], argv[3], argv[4]) != 0) {
        fprintf(stderr, "Failed to enable telnet\n");
        goto out;
    }

    status = 0;
out:
    return status;
}
