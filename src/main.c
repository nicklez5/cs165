#include <tls.h>
#include <stdio.h>
int main() {



    char *the_data;

    struct tls_config* start_tls_obj = tls_config_new();
    int success_error = tls_config_set_ca_file(start_tls_obj,"/home/jackson/CLionProjects/TLSCache/certificates/root.pem");


    return 0;
}
