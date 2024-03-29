#include <pcap/pcap.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
//#include <sys/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
/*
 * Most of this file is the background functionality to open a capture file or to
 * open an inteface for a live capture. You can ignore all this unless you are
 * interested in an example of how pcap works.
 *
 * To use the file, simply insert your code in the "Put your code here" section and
 * create a Makefile for compilation.
 */

/* Maximum time that the OS will buffer packets before giving them to your program. */
#define MAX_BUFFER_TIME_MS (300)

/* Maximum time the program will wait for a packet during live capture.
 * Measured in MAX_BUFFER_TIME_MS units. Program closes when it expires. */
#define MAX_IDLE_TIME 100 /* 100*MAX_BUFFER_TIME_MS idle time at most */

/* Function that creates the structures necessary to perform a packet capture and
 * determines capture source depending on arguments. Function will terminate the
 * program on error, so return value always valid. */
pcap_t* setup_capture(int argc, char *argv[], char *use_file);

/* Cleanup the state of the capture. */
void cleanup_capture(pcap_t *handle);

/* Check for abnormal conditions during capture.
 * 1 returned if a packet is ready, 0 if a packet is not available.
 * Terminates program if an unrecoverable error occurs. */
char valid_capture(int return_value, pcap_t *pcap_handle, char use_file);

int main(int argc, char *argv[]) {

  pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
  struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
  const u_char *packet_data = NULL;       /* Packet data from PCAP */
  int ret = 0;                            /* Return value from library calls */
  char use_file = 0;                      /* Flag to use file or live capture */

  /* Setup the capture and get the valid handle. */
  pcap_handle = setup_capture(argc, argv, &use_file);

  /* Loop through all the packets in the trace file.
   * ret will equal -2 when the trace file ends.
   * ret will never equal -2 for a live capture. */
  ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
  while( ret != -2 ) {
    if( valid_capture(ret, pcap_handle, use_file) ){
      /*
       *
       * this is the ehternet code working
       *
       */
      for(int i = 6; i<12; i++){
        printf("%01x",packet_data[i]);
        if(i<11)
          printf( ":");
      }
      printf(" -> ");
      for(int i =0; i<6; i++){
        printf("%01x",packet_data[i]);
        if(i<5)
          printf( ":");
      }
      printf("\n");
      /* 
       *
       *this is the ipv4 code below
       *
       */
      if(packet_data[12] == 8 && packet_data[13] == 0){
        printf("   [IPv4] ");
        for(int i = 26;i<30;i++){
          printf("%d", packet_data[i]);
          if(i < 29)
            printf(".");
        }
        printf(" -> ");
        for (int i = 30; i<34; i++){
          printf("%d", packet_data[i]);
          if(i< 33)
            printf(".");
        }
        printf("\n");
        if(packet_data[23] == 6){
          printf("   [TCP] ");
          int source  = (packet_data[34]<<8) +packet_data[35];
          int dest = (packet_data[36]<<8) + packet_data[37];
          printf("%d", source);
          printf(" -> ");
          printf("%d", dest);
          if((packet_data[47]&2) == 2)
            printf(" SYN");
          else if((packet_data[47]&1) == 1)
            printf(" FIN");
        }
        else if(packet_data[23] == 17){
          printf("   [UDP] ");
          int source  = (packet_data[34]<<8) +packet_data[35];
          int dest = (packet_data[36]<<8) + packet_data[37];
          printf("%d", source);
          printf(" -> ");
          printf("%d", dest);
        }
        else{ 
          printf("   [");
          printf("%d", packet_data[23]);
          printf("]");
        }
        printf("\n");
      }
      /*
       *
       * ipv6 code
       *
       */
      else if(packet_data[12] == 134 && packet_data[13] == 221){
        printf("   [IPv6] ");
        char ipv6_source[INET6_ADDRSTRLEN];
        char ipv6_hex_source[INET6_ADDRSTRLEN];
        char ipv6_dest[INET6_ADDRSTRLEN];
        char ipv6_hex_dest[INET6_ADDRSTRLEN]; 
        memcpy(ipv6_source, &packet_data[22], INET6_ADDRSTRLEN);
        memcpy(ipv6_dest, &packet_data[38], INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,ipv6_source,ipv6_hex_source, INET6_ADDRSTRLEN );
        inet_ntop(AF_INET6,ipv6_dest,ipv6_hex_dest, INET6_ADDRSTRLEN );
        printf("%s", ipv6_hex_source);
        printf(" -> ");
        printf("%s", ipv6_hex_dest);
        printf("\n");
        if(packet_data[20] == 6){//ipv6 tcp
          printf("   [TCP] ");
          int source  = (packet_data[54]<<8) +packet_data[55];
          int dest = (packet_data[56]<<8) + packet_data[57];
          printf("%d", source);
          printf(" -> ");
          printf("%d", dest);
          if((packet_data[67]&2) == 2)
            printf(" SYN");
          else if((packet_data[67]&1) == 1)
            printf(" FIN");
        }
        else if(packet_data[20]==17){//ipv6 udp
          printf("   [UDP] ");
          int source  = (packet_data[54]<<8) +packet_data[55];
          int dest = (packet_data[56]<<8) + packet_data[57];
          printf("%d", source);
          printf(" -> ");
          printf("%d", dest);
        }
        else{//not ipv6 udp or tcp
          printf("   [");
          printf("%d", packet_data[20]);
          printf("]");
          }
        printf("\n");
      }
      else{ //not ipv4 or ipv6
        int value   = (packet_data[12]<<8)+ packet_data[13];
        printf("    [%d]", value);
        printf("\n");
      }
    }

    /* Get the next packet */
    ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
  }

  cleanup_capture(pcap_handle);
  return 0;
}

/****************************************************************************************
 * You can ignore everything below this unless you are interested.
 ***************************************************************************************/
pcap_t* setup_capture(int argc, char *argv[], char *use_file) {
  char *trace_file = NULL;                /* Trace file to process */
  pcap_t *pcap_handle = NULL;             /* Handle for PCAP library to return */
  char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
  char *dev_name = NULL;                  /* Device name for live capture */

  /* Check command line arguments */
  if( argc > 2 ) {
    fprintf(stderr, "Usage: %s [trace_file]\n", argv[0]);
    exit(-1);
  }
  else if( argc > 1 ){
    *use_file = 1;
    trace_file = argv[1];
  }
  else {
    *use_file = 0;
  }

  /* Open the trace file, if appropriate */
  if( *use_file ){
    pcap_handle = pcap_open_offline(trace_file, pcap_buff);
    if( pcap_handle == NULL ){
      fprintf(stderr, "Error opening trace file \"%s\": %s\n", trace_file, pcap_buff);
      exit(-1);
    }
  }
  /* Lookup and open the default device if trace file not used */
  else{
    dev_name = pcap_lookupdev(pcap_buff);
    if( dev_name == NULL ){
      fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
      exit(-1);
    }

    /* Use buffer length as indication of warning, per pcap_open_live(3). */
    pcap_buff[0] = 0;

    pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, MAX_BUFFER_TIME_MS, pcap_buff);
    if( pcap_handle == NULL ){
      fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
      exit(-1);
    }
    if( pcap_buff[0] != 0 ) {
      printf("Warning: %s\n", pcap_buff);
    }

    printf("Capturing on interface '%s'\n", dev_name);
  }

  return pcap_handle;

}

void cleanup_capture(pcap_t *handle) {
  /* Close the trace file or device */
  pcap_close(handle);
}

char valid_capture(int return_value, pcap_t *pcap_handle, char use_file) {
  static int idle_count = 0;  /* Count of idle periods with no packets */
  char ret = 0;               /* Return value, invalid by default */

  /* A general error occurred */
  if( return_value == -1 ) {
    char err_str[] = "Error processing packet:";
    pcap_perror(pcap_handle, err_str);
    cleanup_capture(pcap_handle);
    exit(-1);
  }

  /* Timeout occured for a live packet capture */
  else if( (return_value == 0) && (use_file == 0) ){
    if( ++idle_count >= MAX_IDLE_TIME ){
      printf("Timeout waiting for additional packets on interface\n");
      cleanup_capture(pcap_handle);
      exit(0);
    }
  }

  /* Unexpected/unknown return value */
  else if( return_value != 1 ) {
    fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", return_value);
    cleanup_capture(pcap_handle);
    exit(-1);
  }
  /* Normal operation, packet arrived */
  else{
    idle_count = 0;
    ret = 1;
  }

  return ret;
}
