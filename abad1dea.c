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

BIO* server_connection = 0;

struct abad1dea_userdata {
    SSL_CTX* ssl_context;
    uint64_t block_size;
    uint64_t block_count;

    char* user;
    char* password;
    char* server;
};

static void request_http(SSL_CTX* ctx, char* server, char* url_suffix, char* user, char* password, char* buffer, ssize_t size_in, ssize_t max_len) {
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

    bool retry_request = false;

    do {
        retry_request = false;
        bool connection_reused = false;

        if(server_connection) {
            size_t alive = BIO_write(server_connection, request, strlen(request));

            if(alive != strlen(request) || BIO_flush(server_connection) != 1) {
                BIO_free_all(server_connection);
                fprintf(stderr, "Connection is dead, create a new one (%lu != %lu)\n", alive, strlen(request));
                server_connection = 0;
            }
            else {
                connection_reused = true;
            }
        }

        if(!server_connection) {
            fprintf(stderr, "Creating new connection ...");
            SSL* ssl;

            if(https) {
                server_connection = BIO_new_ssl_connect(ctx);
                BIO_get_ssl(server_connection, &ssl);

                if(!ssl) {
                    fprintf(stderr, "Can't establish ssl-conection!\n");
                    exit(-2);
                }

                SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
                fprintf(stderr, " SSL -> done\n");
            }
            else {
                server_connection = BIO_new(BIO_s_connect());
                fprintf(stderr, " PLAIN -> done\n");
            }

            BIO_set_conn_hostname(server_connection, host);
            BIO_set_conn_port(server_connection, port);

            if(BIO_do_connect(server_connection) <= 0) {
                fprintf(stderr, "Error connecting to server!\n");
                ERR_print_errors_fp(stderr);
                exit(-3);
            }

            if(https) {
                if(BIO_do_handshake(server_connection) <= 0) {
                    fprintf(stderr, "Error establishing SSL connection!\n");
                    ERR_print_errors_fp(stderr);
                    exit(-4);
                }
            }
        }

        if(!connection_reused) {
            if(BIO_write(server_connection, request, strlen(request)) != (int)strlen(request)) {
                BIO_free_all(server_connection);
                server_connection = 0;
                retry_request = true;
                continue;
            }
        }

        if(size_in) {
            if(BIO_write(server_connection, buffer, size_in) != (int)size_in) {
                BIO_free_all(server_connection);
                server_connection = 0;
                retry_request = true;
                continue;
            }
        }

        memset(buffer, 0, max_len);

        ssize_t data_length = 0;

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

        const int httpBufferSize = 16384;
        char httpBuffer[httpBufferSize];
        memset(httpBuffer, 0, httpBufferSize);
        long bytes_in_buffer = 0;
        long buffer_index = 0;

        for(;;) {
            if(bytes_in_buffer == buffer_index) {
                memset(httpBuffer, 0, httpBufferSize);
                bytes_in_buffer = BIO_read(server_connection, httpBuffer, httpBufferSize);
                buffer_index = 0;

                if(bytes_in_buffer <= 0) {
                    fprintf(stderr, "Connection died ...\n");
                    BIO_free_all(server_connection);
                    server_connection = 0;
                    retry_request = true;
                    break;
                }
            }

            char c = httpBuffer[buffer_index++];

            if(skipSpaces && c == ' ') {
                continue;
            }

            if(lastWasLinebreak && c == '\r') {
            }
            else if(lastWasLinebreak && c == '\n') {
                break;
            }
            else {
                lastWasLinebreak = false;
            }

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

        if(retry_request) {
            continue;
        }

        for(ssize_t i = 0; i < data_length;) {
            if(buffer_index == bytes_in_buffer) {
                memset(httpBuffer, 0, httpBufferSize);
                bytes_in_buffer = BIO_read(server_connection, httpBuffer, httpBufferSize);
                buffer_index = 0;

                if(bytes_in_buffer <= 0) {
                    fprintf(stderr, "Connection died ...\n");
                    BIO_free_all(server_connection);
                    server_connection = 0;
                    retry_request = true;
                    break;
                }
            }

            memcpy(buffer + i, httpBuffer + buffer_index, (bytes_in_buffer - buffer_index) > (max_len - i) ? (max_len - i) : (bytes_in_buffer - buffer_index));
            buffer_index += bytes_in_buffer;
            i += buffer_index;
        }
    } while(retry_request);
}

static int xmp_read(void *buf, u_int32_t len, u_int64_t offset, void *userdata_ptr)
{
    struct abad1dea_userdata* userdata = (struct abad1dea_userdata*)userdata_ptr;

    char suffix_buffer[32];
    snprintf(suffix_buffer, 32, "bytes/%lu/%u", offset, len);

    request_http(userdata->ssl_context, userdata->server, suffix_buffer, userdata->user, userdata->password, buf, 0, len);
    return 0;
}

static int xmp_write(const void *buf, u_int32_t len, u_int64_t offset, void *userdata_ptr)
{
    struct abad1dea_userdata* userdata = (struct abad1dea_userdata*)userdata_ptr;

    char suffix_buffer[32];
    snprintf(suffix_buffer, 32, "bytes/%lu", offset);

    request_http(userdata->ssl_context, userdata->server, suffix_buffer, userdata->user, userdata->password, (char*)buf, len, 0);
    return 0;
}

static struct buse_operations aop = {
    .read = xmp_read,
    .write = xmp_write,
};

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr,
                "Usage:\n"
                "  %s /dev/nbd0 https://api-dev.abad1dea.net:8443/ littlefox@abad1dea.net password\n"
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

    request_http(userdata.ssl_context, userdata.server, "block/count", userdata.user, userdata.password, buffer, 0, sizeof(buffer));
    userdata.block_count = atoi(buffer);

    request_http(userdata.ssl_context, userdata.server, "block/size", userdata.user, userdata.password, buffer, 0, sizeof(buffer));
    userdata.block_size = atoi(buffer);

    printf("Number of blocks: %lu, size of block: %lu\n", userdata.block_count, userdata.block_size);

    aop.size = userdata.block_size * userdata.block_count;

    return buse_main(argv[1], &aop, (void*)&userdata);
}
