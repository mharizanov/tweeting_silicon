#include <user_interface.h>
#include <osapi.h>
#include <c_types.h>
#include <ctype.h>
#include <mem.h>
#include <os_type.h>
#include "httpclient.h"
#include "espmissingincludes.h"
#include "driver/uart.h"
#include "user_config.h"
#include "sntp.h"

#include "ssl_crypto.h"

unsigned char *default_certificate;
unsigned int default_certificate_len = 0;
unsigned char *default_private_key;
unsigned int default_private_key_len = 0;


typedef enum {
	WIFI_CONNECTING,
	WIFI_CONNECTING_ERROR,
	WIFI_CONNECTED,
} tConnState;

LOCAL void ICACHE_FLASH_ATTR setup_wifi_st_mode(void);
static struct ip_info ipConfig;
static ETSTimer WiFiLinker;
static tConnState connState = WIFI_CONNECTING;

const char *WiFiMode[] =
{
		"NULL",		// 0x00
		"STATION",	// 0x01
		"SOFTAP", 	// 0x02
		"STATIONAP"	// 0x03
};

const char *WiFiStatus[] =
{
	    "STATION_IDLE", 			// 0x00
	    "STATION_CONNECTING", 		// 0x01
	    "STATION_WRONG_PASSWORD", 	// 0x02
	    "STATION_NO_AP_FOUND", 		// 0x03
	    "STATION_CONNECT_FAIL", 	// 0x04
	    "STATION_GOT_IP" 			// 0x05
};


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};


char * ICACHE_FLASH_ATTR base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = os_malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

char * ICACHE_FLASH_ATTR replace(
    char const * const original,
    char const * const pattern,
    char const * const replacement
) {
  size_t const replen = strlen(replacement);
  size_t const patlen = strlen(pattern);
  size_t const orilen = strlen(original);

  size_t patcnt = 0;
  const char * oriptr;
  const char * patloc;

  // find how many times the pattern occurs in the original string
  for (oriptr = original; patloc = strstr(oriptr, pattern); oriptr = patloc + patlen)
  {
    patcnt++;
  }

  {
    // allocate memory for the new string
    size_t const retlen = orilen + patcnt * (replen - patlen);
    char * const returned = (char *) os_malloc( sizeof(char) * (retlen + 1) );

    if (returned != NULL)
    {
      // copy the original string,
      // replacing all the instances of the pattern
      char * retptr = returned;
      for (oriptr = original; patloc = strstr(oriptr, pattern); oriptr = patloc + patlen)
      {
        size_t const skplen = patloc - oriptr;
        // copy the section until the occurence of the pattern
        strncpy(retptr, oriptr, skplen);
        retptr += skplen;
        // copy the replacement
        strncpy(retptr, replacement, replen);
        retptr += replen;
      }
      // copy the rest of the string.
      strcpy(retptr, oriptr);
    }
    return returned;
  }
}

static char hex[] = "0123456789abcdef";

  char ICACHE_FLASH_ATTR i2a(char code) {
      return hex[code & 15];
  }

  char * ICACHE_FLASH_ATTR urlencode(const char *upstr )
  {
      char           *buf,
          *pbuf;

     pbuf = buf = (char *)os_malloc( strlen(upstr) * 3 + 1 );

     while(*upstr){
         if( isalnum(*upstr) || *upstr == '-' || *upstr == '_' || *upstr == '.' || *upstr == '~' ){
             *pbuf++ = *upstr;
         }
         else if( *upstr == ' ' ){
             *pbuf++ = '+';
         }
         else{
             *pbuf++ = '%',
             *pbuf++ = i2a(*upstr >> 4),
             *pbuf++ = i2a(*upstr & 15);
         }
         upstr++;
     }
     *pbuf = '\0';

     return buf;
 }

LOCAL void ICACHE_FLASH_ATTR twitter_http_callback(char * response, int http_status, char * full_response)
{
	os_printf("Answers: \r\n");
	if (http_status == 200)
	{
		//os_printf("strlen(response)=%d\r\n", strlen(response));
		//os_printf("strlen(full_response)=%d\r\n", strlen(full_response));
		os_printf("response=%s\r\n", response);
		//os_printf("full_response=%s\r\n", full_response);
		os_printf("---------------------------\r\n");
	}
	else
	{
		os_printf("http_status=%d\r\n", http_status);
		os_printf("strlen(response)=%d\r\n", strlen(response));
		os_printf("strlen(full_response)=%d\r\n", strlen(full_response));
		os_printf("response=%s\r\n", response);
		os_printf("---------------------------\r\n");
	}
}


static ETSTimer prHeapTimer;

static void ICACHE_FLASH_ATTR prHeapTimerCb(void *arg) {
	os_printf("Heap: %ld\n", (unsigned long)system_get_free_heap_size());

	uint32 current_stamp;
	current_stamp = sntp_get_current_timestamp();
	os_printf("sntp: %d, %s \n",current_stamp, sntp_get_real_time(current_stamp));

	static int runonce=0;
	if(runonce) return;
	runonce++;


	const char * consumer_key="consumer_key_here";
	const char * consumer_secret="consumer_secret_here";
	const char * oauth_token="oauth_tokern_here";
	const char * oauth_secret="oauth_secret";
	const char * message = "This tweet is sent by #ESP8266 using #oAuth #TLS #IoT @mharizanov";
	const char * api_version="1.1";

	const char * message_string = replace(replace(replace(message," ","%2520"),"@","%2540"),"#","%2523");
	os_printf("message_string=%s\n",message_string);

	const char * message_post = replace(urlencode(message)," ","+");
	os_printf("message_post=%s\n",message_post);

	char timestamp[32];
	os_sprintf(timestamp,"%d", sntp_get_current_timestamp() );

	os_printf("timestamp=%s\n",timestamp);

	int len;
	char nonce[32];
	os_sprintf(nonce, "%s", base64_encode(timestamp,strlen(timestamp), &len));
	nonce[len]=0x0;

	char* tmp=replace(nonce,"=","");
	os_sprintf(nonce,"%s",tmp);
	tmp=replace(nonce,"/","");
	os_sprintf(nonce,"%s",tmp);
	tmp=replace(nonce,"+","");
	os_sprintf(nonce,"%s",tmp);
	os_printf("nonce=%s\n",nonce);

	char signature_base_string[512];
	os_sprintf(signature_base_string, "POST&https%%3A%%2F%%2Fapi.twitter.com%%2F%s%%2Fstatuses%%2Fupdate.json&oauth_consumer_key%%3D%s%%26oauth_nonce%%3D%s%%26oauth_signature_method%%3DHMAC-SHA1%%26oauth_timestamp%%3D%s%%26oauth_token%%3D%s%%26oauth_version%%3D1.0%%26status%%3D%s", api_version, consumer_key,  nonce, timestamp, oauth_token, message_string);

	os_printf("signature_base_strilng=%s\n",signature_base_string);

	char signature_key[128];
	os_sprintf(signature_key,"%s&%s",consumer_secret,oauth_secret);
	os_printf("signature key: %s\n",signature_key);

	//Handle key size > block size (64 byte)
	uint8_t digestkey[32];
	SHA1_CTX context;
	SHA1_Init(&context);
	SHA1_Update(&context, signature_key, strlen(signature_key));
	SHA1_Final(digestkey, &context);

	uint8_t digest[32];
	ssl_hmac_sha1(signature_base_string,strlen(signature_base_string),digestkey,SHA1_SIZE,digest);

	os_printf("oauth_signature ssl_hmac_sha1: ");

	for (int i = 0; i < SHA1_SIZE; i++)
	{
		os_printf("%02X", digest[i]);
	}

	os_printf("\n");


	unsigned char oauth_signature[255];
	os_sprintf(oauth_signature, "%s", base64_encode(digest,SHA1_SIZE, &len));
	oauth_signature[len]=0x00;

	tmp=replace(oauth_signature,"+","%2B");
	os_sprintf(oauth_signature,"%s",tmp);

	tmp=replace(oauth_signature,"/","%2F");
	os_sprintf(oauth_signature,"%s",tmp);

	tmp=replace(oauth_signature,"=","%3D");
	os_sprintf(oauth_signature,"%s",tmp);

	os_printf("oauth_signature=%s\n",oauth_signature);

	char headers[512];

	os_sprintf(headers,"Authorization: OAuth oauth_consumer_key=\"%s\", oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"%s\", oauth_token=\"%s\", oauth_version=\"1.0\"\r\nContent-Type: application/x-www-form-urlencoded\r\n", \
			consumer_key,nonce,oauth_signature,timestamp,oauth_token );

	os_printf("headers: %s\n",headers);

	char post_data[128]="";
	os_sprintf(post_data,"status=%s",message_post);

	http_post("https://api.twitter.com/1.1/statuses/update.json", post_data, headers, twitter_http_callback);
}

static void ICACHE_FLASH_ATTR wifi_check_ip(void *arg)
{
	os_timer_disarm(&WiFiLinker);
	switch(wifi_station_get_connect_status())
	{
		case STATION_GOT_IP:
			wifi_get_ip_info(STATION_IF, &ipConfig);
			if(ipConfig.ip.addr != 0) {
				connState = WIFI_CONNECTED;
				os_printf("WiFi connected\r\n");
			} else {
				connState = WIFI_CONNECTING_ERROR;
				os_printf("WiFi connected, ip.addr is null\r\n");
			}
			break;
		case STATION_WRONG_PASSWORD:
			connState = WIFI_CONNECTING_ERROR;
			os_printf("WiFi connecting error, wrong password\r\n");
			break;
		case STATION_NO_AP_FOUND:
			connState = WIFI_CONNECTING_ERROR;
			os_printf("WiFi connecting error, ap not found\r\n");
			break;
		case STATION_CONNECT_FAIL:
			connState = WIFI_CONNECTING_ERROR;
			os_printf("WiFi connecting fail\r\n");
			break;
		default:
			connState = WIFI_CONNECTING;
			os_printf("WiFi connecting...\r\n");
	}
	os_timer_setfn(&WiFiLinker, (os_timer_func_t *)wifi_check_ip, NULL);
	os_timer_arm(&WiFiLinker, 2000, 0);
}


LOCAL void ICACHE_FLASH_ATTR setup_wifi_st_mode(void)
{
	wifi_set_opmode(STATION_MODE);
	struct station_config stconfig;
	wifi_station_disconnect();
	wifi_station_dhcpc_stop();
	if(wifi_station_get_config(&stconfig))
	{
		os_memset(stconfig.ssid, 0, sizeof(stconfig.ssid));
		os_memset(stconfig.password, 0, sizeof(stconfig.password));
		os_sprintf(stconfig.ssid, "%s", WIFI_CLIENTSSID);
		os_sprintf(stconfig.password, "%s", WIFI_CLIENTPASSWORD);
		if(!wifi_station_set_config(&stconfig))
		{
			os_printf("ESP8266 not set station config!\r\n");
		}
	}
	wifi_station_connect();
	wifi_station_dhcpc_start();
	wifi_station_set_auto_connect(1);
	os_printf("ESP8266 in STA mode configured.\r\n");
}

int ipaddr_aton (const char *cp, ip_addr_t *addr);

void user_init(void)
{
	// Configure the UART
	uart_init(BIT_RATE_115200,0);
	// Enable system messages
	system_set_os_print(1);
	os_printf("\r\nSystem init...\r\n");

	if(wifi_get_opmode() != STATION_MODE)
	{
		os_printf("ESP8266 is %s mode, restarting in %s mode...\r\n", WiFiMode[wifi_get_opmode()], WiFiMode[STATION_MODE]);
		setup_wifi_st_mode();
	}
	if(wifi_get_phy_mode() != PHY_MODE_11N)
		wifi_set_phy_mode(PHY_MODE_11N);
	if(wifi_station_get_auto_connect() == 0)
		wifi_station_set_auto_connect(1);

	// Wait for Wi-Fi connection
	os_timer_disarm(&WiFiLinker);
	os_timer_setfn(&WiFiLinker, (os_timer_func_t *)wifi_check_ip, NULL);
	os_timer_arm(&WiFiLinker, 1000, 0);

	//Start NTP, needed for time stamping oAuth message
	ip_addr_t *addr = (ip_addr_t *)os_zalloc(sizeof(ip_addr_t));
	sntp_setservername(0, "us.pool.ntp.org"); // set server 0 by domain name
	sntp_setservername(1, "ntp.sjtu.edu.cn"); // set server 1 by domain name
	ipaddr_aton("210.72.145.44", addr);
	sntp_setserver(2, addr); // set server 2 by IP address

	sntp_init();
	sntp_set_timezone(3);
	os_free(addr);

	//Schedule the Tweet in a while when WiFi connection is up
	os_timer_disarm(&prHeapTimer);
	os_timer_setfn(&prHeapTimer, prHeapTimerCb, NULL);
	os_timer_arm(&prHeapTimer, 8000, 0);

	os_printf("System init done.\n");
}


void ICACHE_FLASH_ATTR user_rf_pre_init() {
}


