/*
 * abad1dea - block-device driver for Linux using BUSE
 * Copyright (C) 2016 LittleFox
 *
 * This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <resolv.h>
#include <unistd.h>

#include "buse.h"

struct abad1dea_userdata {
    SSL_CTX* ssl_context;
    int block_size;
    uint64_t block_count;

    char* user;
    char* password;
    char* server;
};

static void request_http(SSL_CTX* ctx, char* server, char* url_suffix, char* user, char* password, char* buffer, size_t size_in, size_t max_len) {
    size_t server_len = strlen(server);
    
    char host[255];
    memset(host, 0, 255);

    char port[6];
    memset(port, 0, 6);

    char url[255];
    memset(url, 0, 255);

    bool https = false;

    bool inProtocol = true;
    bool inHost = false;
    bool inPort = false;
    bool inURL = false;
    int skip = 0;
    int hostIndex = 0;
    int portIndex = 0;
    int urlIndex = 0;

    for(size_t i = 0; i < server_len; i++) {
        if(skip) {
            --skip;
            continue;
        }

        if(inProtocol) {
            if(server[i] == ':') {
                if(server[i] == ':' && server[i-1] == 's') {
                    https = true;
                }
                else if(server[i] == ':' && server[i-1] == 'p') {
                    https = false;
                }

                skip = 2;
                inHost = true;
                inProtocol = false;
                continue;
            }
        }
        
        if(inHost) {
            if(server[i] == '/') {
                inURL = true;
                inHost = false;
            }
            else if(server[i] == ':') {
                inPort = true;
                inHost = false;
                continue;
            }
            else {
                host[hostIndex++] = server[i];
            }
        }
       
        if(inPort) {
            if(server[i] >= '0' && server[i] <= '9') {
                port[portIndex++] = server[i];
            }
            else {
                inPort = false;
                inURL = true;
            }
        }

        if(inURL) {
            url[urlIndex++] = server[i];
        }
    }

    memcpy(url + urlIndex, url_suffix, strlen(url_suffix));

    if(strlen(port) == 0) {
        memcpy(port, https ? "https" : "http", https ? 5 : 4);
    }

    char authorization_buffer[255];
    snprintf(authorization_buffer, 255, "%s:%s", user, password);
    
    char authorization[300];
    memset(authorization, 0, 300);
    // hidden gem in resolv.h
    b64_ntop((u_char*)authorization_buffer, strlen(authorization_buffer), authorization, 299);
    
    size_t initial_request_size = 1024;
    char* request = malloc(initial_request_size);

    char* format_string = "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Length: %lu\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";

    size_t actual_request_length = snprintf(request, initial_request_size, format_string, size_in ? "PUT" : "GET", url, host, authorization, size_in);

    if(actual_request_length > initial_request_size) {
        free(request);
        request = malloc(actual_request_length);
        snprintf(request, initial_request_size, format_string, size_in ? "PUT" : "GET", url, host, authorization, size_in);
    }

    BIO* bio;
    SSL* ssl;

    if(https) {
        bio = BIO_new_ssl_connect(ctx);
        BIO_get_ssl(bio, &ssl);

        if(!ssl) {
            fprintf(stderr, "Can't establish ssl-conection!\n");
            exit(-1);
        }

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    }
    else {
        bio = BIO_new(BIO_s_connect());
    }
 
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, port);
   
    if(BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to server!\n");
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    if(https) {
        if(BIO_do_handshake(bio) <= 0) {
            fprintf(stderr, "Error establishing SSL connection!\n");
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
    }

    BIO_write(bio, request, strlen(request));

    if(size_in) {
        BIO_write(bio, buffer, size_in);
    }

    memset(buffer, 0, max_len);
    
    size_t data_length = 0;

    // read headers
    char headerName[64];
    memset(headerName, 0, 64);
    char headerValue[192];
    memset(headerValue, 0, 192);

    bool inName = false;
    bool inValue = false;
    bool skipSpaces = false;
    bool lastWasLinebreak = false;
    bool firstLine = true;
    int headerNameIndex = 0;
    int headerValueIndex = 0;

    char httpBuffer[512];
    memset(httpBuffer, 0, sizeof(httpBuffer));
    int bytes_in_buffer = 0;

    char* bufferPtr = httpBuffer;

    for(;;) {
        if(bytes_in_buffer == 0) {
            memset(httpBuffer, 0, sizeof(httpBuffer));
            bytes_in_buffer = BIO_read(bio, httpBuffer, sizeof(httpBuffer));
            bufferPtr = httpBuffer;
        }

        char c = *(bufferPtr++);
        bytes_in_buffer--;

        if(skipSpaces && c == ' ') {
            continue;
        }

        if(lastWasLinebreak && c == '\r') {
            bufferPtr++;
            bytes_in_buffer--;
            break;
        }

        lastWasLinebreak = false;

        if(firstLine) {
            if(c == '\n') {
                firstLine = false;
                inName = true;
            }
        }

        if(inName) {
            if(c == ':') {
                inName = false;
                inValue = true;
                skipSpaces = true;
                continue;
            }

            headerName[headerNameIndex++] = tolower(c);
        }

        if(inValue) {
            skipSpaces = false;

            if(c == '\r') {
                continue;
            }
            else if(c == '\n') {
                inName = true;
                inValue = false;
                lastWasLinebreak = true;

                if(strcmp(headerName, "content-length") == 0) {
                    data_length = atoi(headerValue);
                }
    
                memset(headerName, 0, sizeof(headerName));
                memset(headerValue, 0, sizeof(headerValue));

                headerNameIndex = 0;
                headerValueIndex = 0;
            }
            else {
                headerValue[headerValueIndex++] = c;
            }
        }
    }

    if(bytes_in_buffer > data_length) {
        bytes_in_buffer = data_length;
    }

    memcpy(buffer, bufferPtr, bytes_in_buffer > max_len ? max_len : bytes_in_buffer);

    if(data_length - bytes_in_buffer) {
        BIO_read(bio, buffer + bytes_in_buffer, (data_length - bytes_in_buffer) > max_len ? max_len : (data_length - bytes_in_buffer));
    }

    BIO_free_all(bio);
}

static int xmp_read(void *buf, u_int32_t len, u_int64_t offset, void *userdata_ptr)
{
    struct abad1dea_userdata* userdata = (struct abad1dea_userdata*)userdata_ptr;

    if(len % userdata->block_size != 0 || (len % userdata->block_size) != 0) {
        exit(-1);
    }

    int numblocks   = len / userdata->block_size;
    int start_block = offset / userdata->block_size;

    char* buffer = mmap(NULL, numblocks * userdata->block_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    for(int i = start_block; i < start_block + numblocks; i++) {
        pid_t pid = fork();
        
        if(pid == 0) {
            char suffix_buffer[32];
            snprintf(suffix_buffer, 32, "%d", i);

            request_http(userdata->ssl_context, userdata->server, suffix_buffer, userdata->user, userdata->password, buffer + ((i - start_block) * userdata->block_size), 0, userdata->block_size);

            printf("Block %d read from server\n", i);
            exit(0);
        }
    }

    int status;
    pid_t pid;
    while(numblocks > 0) {
        pid = wait(&status);
        --numblocks;
        printf("%d children left ...\n", numblocks);
    }

    memcpy(buf, buffer, len);
    munmap(buffer, numblocks * userdata->block_size);
    return 0;
}

static int xmp_write(const void *buf, u_int32_t len, u_int64_t offset, void *userdata_ptr)
{
    struct abad1dea_userdata* userdata = (struct abad1dea_userdata*)userdata_ptr;

    if(len % userdata->block_size != 0 || (len % userdata->block_size) != 0) {
        exit(-1);
    }

    int numblocks   = len / userdata->block_size;
    int start_block = offset / userdata->block_size;
    
    for(int i = start_block; i < start_block + numblocks; i++) {
        pid_t pid = fork();

        if(pid == 0) {
            char suffix_buffer[32];
            snprintf(suffix_buffer, 32, "%d", i);

            request_http(userdata->ssl_context, userdata->server, suffix_buffer, userdata->user, userdata->password, (char*)buf + ((i - start_block) * userdata->block_size), userdata->block_size, 0);

            printf("Block %d written to server\n", i);
            exit(0);
        }
    }

    int status;
    pid_t pid;
    while(numblocks > 0) {
        pid = wait(&status);
        --numblocks;
        printf("%d children left ...\n", numblocks);
    }

    return 0;
}

static struct buse_operations aop = {
  .read = xmp_read,
  .write = xmp_write,
  .size = 128 * 1024 * 1024,
};

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, 
            "Usage:\n"
            "  %s /dev/nbd0 https://api-dev.abad1dea.net:8080/block/ littlefox@abad1dea.net password\n"
            "Don't forget to load nbd kernel module (`modprobe nbd`) and\n"
            "run as root.\n", argv[0]);
        return 1;
    }
   
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    struct abad1dea_userdata userdata;
    userdata.server = argv[2];
    userdata.user = argv[3];
    userdata.password = argv[4];
    userdata.ssl_context = SSL_CTX_new(TLSv1_2_client_method());

    char buffer[32];
    
    request_http(userdata.ssl_context, userdata.server, "count", userdata.user, userdata.password, buffer, 0, sizeof(buffer));
    userdata.block_count = atoi(buffer);

    request_http(userdata.ssl_context, userdata.server, "size", userdata.user, userdata.password, buffer, 0, sizeof(buffer));
    userdata.block_size = atoi(buffer);

    printf("Number of blocks: %lu, size of block: %d\n", userdata.block_count, userdata.block_size);

    aop.size = userdata.block_size * userdata.block_count;

    return buse_main(argv[1], &aop, (void*)&userdata);
}
