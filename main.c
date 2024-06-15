#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define QUEUE_NUM 0

unsigned char *file_nibbles;
int file_nibble_count = 0;

const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char* command_prefix = "ping";
const char* command_options = "-i 0.002";
const char* command_postfix = "| bash -c 't=($(echo \"$(cat)\"|grep -oP \"ttl=\\K\\d+\"));m=$(printf \"%d\\n\" \"${t[@]}\"|sort -n|head -1);for ((i=0;i<${#t[@]}-1;i++));do if ((t[i]==m&&t[i+1]==m));then p=$i;break;fi;done;a=$((${#t[@]}));b=();for ((i=0;i<a;i++));do b+=(\"${t[(a+i+p+2)%a]}\");done;s=\"\";c=0;for ((i=0;i<${#b[@]}-4;i+=2));do u=$((b[i]-m));l=$((i+1<${#b[@]}?b[i+1]-m:0));h=$(printf \"%02x\" $((u<<4|l)));s+=\"$h\";c=$((((c+u+l)%256)&0x0f));done;k=$((t[p-1]-m));if ((c!=k));then echo \"Checksum mismatch. The data may be corrupted.\";fi;printf %b $(printf %s \"$s\"|while read -r -n2 c;do printf \"\\x$c\";done)|base64 -d -w0'";
const char* powerhsell_thing_p2= ")).Options.Ttl };$m=($t|Sort-Object)[0];$p=-1;for($i=0;$i-lt$t.Count-1;$i++){if($t[$i]-eq$m-and$t[$i+1]-eq$m){$p=$i;break}};$b=@();$a=$t.Count;for($i=0;$i-lt$a;$i++){$b+=$t[($a+$i+$p+2)%$a]};$h=\"\";$c=0;for($i=0;$i-lt$b.Count-4;$i+=2){$u=$b[$i]-$m;$l=if($i+1-lt$b.Count){$b[$i+1]-$m}else{0};$q=\"{0:X2}\"-f($u-shl4-bor$l);$h+=$q;$c=(($c+$u+$l)%256)-band0x0f};$k=$t[$p-1]-$m;if($c-ne$k){\"Checksum mismatch. The data may be corrupted.\"}else{$y=@();for($i=0;$i-lt$h.Length;$i+=2){$e=[Convert]::ToByte($h.Substring($i,2),16);$y+=$e};$g=[System.Text.Encoding]::UTF8.GetString($y);[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($g))}";

unsigned short ip_checksum(unsigned short *ptr, int nbytes) {
	unsigned long sum;
	unsigned short oddbyte;
	unsigned short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (unsigned short)~sum;

	return answer;
}

// stolen from https://github.com/jwerle/b64.c/blob/master/encode.c
void base64_encode(const unsigned char *data, int len, char *encoded_data) {
	int i = 0, j = 0;
	int enc_len = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	while (len--) {
		a3[i++] = *(data++);
		if (i == 3) {
			a4[0] = (a3[0] & 0xfc) >> 2;
			a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
			a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
			a4[3] = a3[2] & 0x3f;

			for (i = 0; i < 4; i++) {
				encoded_data[enc_len++] = base64_chars[a4[i]];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a4[0] = (a3[0] & 0xfc) >> 2;
		a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
		a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
		a4[3] = a3[2] & 0x3f;

		for (j = 0; j < i + 1; j++) {
			encoded_data[enc_len++] = base64_chars[a4[j]];
		}

		while (i++ < 3) {
			encoded_data[enc_len++] = '=';
		}
	}

	encoded_data[enc_len] = '\0';
}

static u_int32_t print_pkt(struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		struct iphdr *ip_header = (struct iphdr *)data;
		if (ip_header->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp_header = (struct icmphdr *)(data + (ip_header->ihl * 4));
			unsigned short seq_num = ntohs(icmp_header->un.echo.sequence);
			seq_num = seq_num - 1;

			ip_header->ttl = 64 + file_nibbles[(seq_num) % file_nibble_count];
			ip_header->check = 0;
			ip_header->check = ip_checksum((unsigned short *)ip_header, ip_header->ihl * 4);
			printf("Modified ICMP packet: TTL set to %d\n", ip_header->ttl);
		}
	}
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	u_int32_t id = print_pkt(nfa);
	unsigned char *pktData;
	int len = nfq_get_payload(nfa, &pktData);
	return nfq_set_verdict(qh, id, NF_ACCEPT, len, pktData);
}


void cleanup(int signum) {
	printf("\nCaught signal %d. Cleaning up...\n", signum);
	system("iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0");
	exit(1);
}

int main(int argc, char **argv) {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	if (getuid() != 0) {
		fprintf(stderr, "This program must be run as root.\n");
		exit(1);
	}

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGSEGV, cleanup);
	signal(SIGABRT, cleanup);

	system("iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0");

	char *file_path = NULL;
	char *ip_address = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "f:i:")) != -1) {
		switch (opt) {
			case 'f':
				file_path = optarg;
				break;
			case 'i':
				ip_address = optarg;
				break;
			default:
				fprintf(stderr, "Usage: %s [-f file_path] [-i ip_address]\n", argv[0]);
				exit(1);
		}
	}

	if (ip_address == NULL) {
		fprintf(stderr, "Error: IP address not provided. Use the -i option to specify the IP address.\n");
		exit(1);
	}

	if (file_path == NULL) {
		fprintf(stderr, "Error: Input file not provided. Use the -f option to specify the file to serve.\n");
		exit(1);
	}

	FILE *file = fopen(file_path, "rb");
	if (file == NULL) {
		fprintf(stderr, "Error opening file: %s\n", file_path);
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	rewind(file);

	unsigned char *file_bytes = (unsigned char *)malloc(file_size);
	fread(file_bytes, 1, file_size, file);
	fclose(file);

	char *encoded_file = (char *)malloc((file_size * 4 / 3) + 4);
	base64_encode(file_bytes, file_size, encoded_file);

	file_nibble_count = strlen(encoded_file) * 2+4;
	file_nibbles = (unsigned char *)malloc(file_nibble_count+4);

	printf("Base64 Encoded File: %s\n", encoded_file);

	uint8_t checksum=0;

	for (int i = 0; i < strlen(encoded_file); i++) {
		file_nibbles[i * 2] = encoded_file[i] >> 4;
		file_nibbles[i * 2 + 1] = encoded_file[i] & 0x0F;
		/*printf("0x%01x \n",encoded_file[i]);*/
		checksum+=(encoded_file[i] >> 4) + (encoded_file[i] & 0x0F) ;
	}

	checksum=checksum&0x0F;
	printf("-------------------\n");
	file_nibbles[file_nibble_count-4]=0;
	file_nibbles[file_nibble_count-3]=checksum;
	file_nibbles[file_nibble_count-2]=0;
	file_nibbles[file_nibble_count-1]=0;
	/*for (int i = 0; i < file_nibble_count; i++) {*/
	/*printf("%d %d \n",i, file_nibbles[i]+64);*/
	/*printf("%d \n", file_nibbles[i]);*/
	/*}*/
	printf("checksum: %d\n",checksum);

	free(file_bytes);
	free(encoded_file);
	printf("Number of nibbles: %d\n\n", file_nibble_count);


	char command[1024];
	snprintf(command, sizeof(command), "%s %s -c %d %s %s",
			command_prefix, ip_address, file_nibble_count, command_options, command_postfix);

	printf("Bash Command: \n\n%s \n\n", command);

	printf("Powershell Command: \n\n$t = 1..%d | ForEach-Object { ([System.Net.NetworkInformation.Ping]::new().Send('%s'%s \n\n",file_nibble_count,ip_address, powerhsell_thing_p2);

	// stolen from https://github.com/irontec/netfilter-nfqueue-samples/blob/master/sample-helloworld.c
	printf("Opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "Error opening library handle\n");
		exit(1);
	}

	printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "Error unbinding nf_queue handler\n");
		exit(1);
	}

	printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "Error binding nf_queue handler\n");
		exit(1);
	}

	printf("Binding this socket to queue '%d'\n", QUEUE_NUM);
	qh = nfq_create_queue(h, QUEUE_NUM, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "Error binding to queue %d\n", QUEUE_NUM);
		exit(1);
	}

	printf("Setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	printf("Unbinding from queue %d\n", QUEUE_NUM);
	nfq_destroy_queue(qh);

	printf("Closing library handle\n");
	nfq_close(h);

	if (file_path != NULL) {
		free(file_nibbles);
	}

	exit(0);
}
