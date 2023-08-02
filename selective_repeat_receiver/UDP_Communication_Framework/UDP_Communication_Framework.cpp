// UDP_Communication_Framework.cpp : Defines the entry point for the console application.
//
#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <chrono>
#include <thread>
#include "ws2tcpip.h"
#include <boost/crc.hpp>
#include "md5.h"
#include "md5.c"

#define TARGET_IP	"147.32.217.51"

#define RECEIVER

#ifdef RECEIVER
#define TARGET_PORT 14001
#define LOCAL_PORT 15000
//#define TARGET_PORT 15001
//#define LOCAL_PORT 14000
#endif // RECEIVER

#define BUFFERS_LEN 1024
#define BUFFERS_FILE_LEN 1016
#define BUFFERS_FILE_DATA_LEN 1012
#define BUFFERS_LEN_WITHOUT_CRC 1020
#define HASH_LEN 16
#define WINDOW_SIZE 5

typedef struct {
	char buffer[BUFFERS_LEN];
	bool is_empty;
} stored_packet_t;


void tochararr(unsigned int x, unsigned char* res)
{
	/*Function writes each byte of int x into char given array*/

	res[0] = res[1] = res[2] = res[3] = 0;
	for (int i = 0; i < 32; i++) {
		int b = ((1 << i) & x);
		b >>= ((i / 8) * 8);
		res[i / 8] |= b;
	}
	return;
}

int to_int(unsigned char letter0, unsigned char letter1, unsigned char letter2, unsigned char letter3)
{
	/*Function decodes 4 bytes into single integer*/

	int res = letter0 | (letter1 << 8) | (letter2 << 16) | (letter3 << 24);
	return res;
}

void make_positive_ack(int decoded_pack_num, char ack_buffer[BUFFERS_LEN]) {
	// Create CRC32 object
	boost::crc_32_type crc32;
	unsigned char num[4] = { 0 };
	const char* pos_ack = "ack";

	memset(ack_buffer, 0, BUFFERS_LEN);

	tochararr(decoded_pack_num, num);
	//Set packet nuumber to first four bytes
	for (int i = 0; i < 4; i++) {
		ack_buffer[i] = num[i];
	}
	for (int i = 0; i < strlen(pos_ack); i++) {
		ack_buffer[i + 4] = pos_ack[i];
	}
	// Get CRC
	crc32.process_bytes(ack_buffer, BUFFERS_LEN_WITHOUT_CRC);
	unsigned long crc_value = crc32.checksum();
	//printf("CRC ack: %lu\n", crc_value);
	tochararr(crc_value, num);

	//Set crc to the last four bytes
	for (int i = 0; i < 4; i++) {
		ack_buffer[i + BUFFERS_LEN_WITHOUT_CRC] = num[i];
	}
}

void make_negative_ack(int decoded_pack_num, char ack_buffer[BUFFERS_LEN]) {
	// Create CRC32 object
	boost::crc_32_type crc32;
	unsigned char num[4] = { 0 };
	const char* pos_ack = "nac";

	memset(ack_buffer, 0, BUFFERS_LEN);

	tochararr(decoded_pack_num, num);
	//Set packet nuumber to first four bytes
	for (int i = 0; i < 4; i++) {
		ack_buffer[i] = num[i];
	}
	for (int i = 0; i < strlen(pos_ack); i++) {
		ack_buffer[i + 4] = pos_ack[i];
	}
	// Get CRC
	crc32.process_bytes(ack_buffer, BUFFERS_LEN_WITHOUT_CRC);
	unsigned long crc_value = crc32.checksum();
	//printf("CRC nack: %lu\n", crc_value);
	tochararr(crc_value, num);

	//Set crc to second four bytes
	for (int i = 0; i < 4; i++) {
		ack_buffer[i + BUFFERS_LEN_WITHOUT_CRC] = num[i];
	}
}

void print_hash(uint8_t* p) {
	for (unsigned int i = 0; i < 16; ++i) {
		printf("%02x", p[i]);
	}
	printf("\n");
}

unsigned long get_crc(char buffer_rx[BUFFERS_LEN]) {
	boost::crc_32_type crc32;
	unsigned long crc_value = 0;
	crc32.process_bytes(buffer_rx, BUFFERS_LEN_WITHOUT_CRC);
	crc_value = crc32.checksum();
	crc32.reset();
	return crc_value;
}

void init_received_packets(stored_packet_t received_packets[WINDOW_SIZE]) {
	for (int i = 0; i < WINDOW_SIZE; i++) {
		memset(received_packets[i].buffer, 0, BUFFERS_LEN);
		received_packets[i].is_empty = true;
	}
}


void check_packet_in_received_packets(stored_packet_t received_packets[WINDOW_SIZE], int* pack_num, int* num_of_pack_stored, FILE* new_f) {
	printf("Checking packet in array\n");
	while (1) {
		bool find_packet = false;
		for (int i = 0; i < WINDOW_SIZE; i++) {
			if (received_packets[i].is_empty == true) {
				//printf("Index: %i - NULL\n", i);
				continue;
			}

			int decoded_pack_num = to_int(received_packets[i].buffer[0], received_packets[i].buffer[1], received_packets[i].buffer[2], received_packets[i].buffer[3]);
			//printf("Index: %i - %i\n", i, decoded_pack_num);
			if (decoded_pack_num == (*pack_num)) {
				int decoded_data_size = to_int(received_packets[i].buffer[4], received_packets[i].buffer[5], received_packets[i].buffer[6], received_packets[i].buffer[7]);
				printf("Writing to file\n");
				fwrite(received_packets[i].buffer + 8, 1, decoded_data_size, new_f);
				memset(received_packets[i].buffer, 0, BUFFERS_LEN);
				received_packets[i].is_empty = true;
				(*pack_num)++;
				(*num_of_pack_stored)--;
				find_packet = true;
			}
		}

		if (find_packet == false) {
			break;
		}
	}
}

bool check_if_decoded_num_is_in_array(stored_packet_t received_packets[WINDOW_SIZE], int decoded_pack_num) {
	bool result = false;
	char buffer[BUFFERS_LEN];
	memset(buffer, 0, BUFFERS_LEN);


	for (int i = 0; i < WINDOW_SIZE; i++) {
		memcpy(buffer, received_packets[i].buffer, BUFFERS_LEN);
		int pack_num = to_int(buffer[0], buffer[1], buffer[2], buffer[3]);
		if (decoded_pack_num == pack_num) {
			result = true;
			break;
		}
		memset(buffer, 0, BUFFERS_LEN);
	}

	return result;
}

void calculate_current_hash(char file_name[BUFFERS_FILE_LEN], uint8_t hash_current[HASH_LEN]) {
	FILE* f = fopen(file_name, "rb");
	if (f == NULL) {
		perror("Can't open file");
		exit(1);
	}

	md5File(f, hash_current);
	fclose(f);
}

void check_hash(uint8_t hash_current[HASH_LEN], uint8_t hash_received[HASH_LEN]) {
	printf("Hash received: ");
	print_hash(hash_received);
	printf("\nHash current: ");
	print_hash(hash_current);

	if (memcmp(hash_current, hash_received, HASH_LEN) == 0) {
		printf("Hash codes are same\n");
	}
	else {
		printf("Hash differs\n");
	}
}

void InitWinsock()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
}

//**********************************************************************
int main()
{
	SOCKET socketS;

	InitWinsock();

	struct sockaddr_in local;
	struct sockaddr_in from;

	int fromlen = sizeof(from);
	local.sin_family = AF_INET;
	local.sin_port = htons(LOCAL_PORT);
	local.sin_addr.s_addr = INADDR_ANY;


	socketS = socket(AF_INET, SOCK_DGRAM, 0);
	if (bind(socketS, (sockaddr*)&local, sizeof(local)) != 0) {
		printf("Binding error!\n");
		getchar(); //wait for press Enter
		return 1;
	}
	//**********************************************************************

#ifdef RECEIVER
	//Binding udp
	sockaddr_in addrDest;
	addrDest.sin_family = AF_INET;
	addrDest.sin_port = htons(TARGET_PORT);
	InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);

	char buffer_rx[BUFFERS_LEN];
	char buffer_tx[BUFFERS_LEN];
	char buffer_wr[BUFFERS_LEN];
	char buffer_stop[BUFFERS_FILE_DATA_LEN];
	char file_name[BUFFERS_FILE_LEN];
	char hash_received_buffer[BUFFERS_FILE_LEN];
	char ack_buffer[BUFFERS_LEN];
	stored_packet_t received_packets[WINDOW_SIZE];
	init_received_packets(received_packets);
	int pack_num = 1;

	printf("Waiting for datagram ...\n");
	
	//Receive filename
	while (1) {
		memset(buffer_rx, 0, BUFFERS_LEN);
		if (recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen) == SOCKET_ERROR) {
			printf("Socket error!\n");
			getchar();
			return 1;
		}
		memset(file_name, 0, BUFFERS_FILE_LEN);
		int decoded_pack_num = to_int(buffer_rx[0], buffer_rx[1], buffer_rx[2], buffer_rx[3]);
		unsigned long decoded_crc = to_int(buffer_rx[1020], buffer_rx[1021], buffer_rx[1022], buffer_rx[1023]);
		memcpy(file_name, buffer_rx + 4, BUFFERS_FILE_LEN);
		printf("DECODED CRC: %lu\n", decoded_crc);
		// Get CRC
		unsigned long crc_value = get_crc(buffer_rx);
		printf("CRC: %lu\n", crc_value);
		if (crc_value != decoded_crc) {
			//Send negative ack
			printf("Sending negative ack\n");
			make_negative_ack(decoded_pack_num, ack_buffer);
			sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
			continue;
		}
		printf("Sending positive ack\n");
		//Send positive ack
		make_positive_ack(decoded_pack_num, ack_buffer);
		sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
		printf("Decoded packet number: %i\n", decoded_pack_num);
		printf("Packet number: %i\n", pack_num);
		if (pack_num == decoded_pack_num) {
			pack_num++;
			break;
		}
	}
	printf("File Name: %s\n", file_name);
	
	
	//Receiving hash
	while (1) {
		memset(buffer_rx, 0, BUFFERS_LEN);
		if (recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen) == SOCKET_ERROR) {
			printf("Socket error!\n");
			getchar();
			return 1;
		}
		memset(hash_received_buffer, 0, BUFFERS_FILE_LEN);
		int decoded_pack_num = to_int(buffer_rx[0], buffer_rx[1], buffer_rx[2], buffer_rx[3]);
		unsigned long decoded_crc = to_int(buffer_rx[1020], buffer_rx[1021], buffer_rx[1022], buffer_rx[1023]);
		memcpy(hash_received_buffer, buffer_rx + 4, BUFFERS_FILE_LEN);
		// Get CRC
		unsigned long crc_value = get_crc(buffer_rx);
		//printf("CRC: %lu\n", crc_value);
		if (crc_value != decoded_crc) {
			//Send negative ack
			printf("Sending negative ack\n");
			make_negative_ack(pack_num, ack_buffer);
			sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
			continue;
		}
		printf("Sending positive ack\n");
		//Send positive ack
		make_positive_ack(decoded_pack_num, ack_buffer);
		sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
		printf("Decoded packet number: %i\n", decoded_pack_num);
		printf("Packet number: %i\n", pack_num);
		if (pack_num == decoded_pack_num) {
			pack_num++;
			break;
		}
	}

	FILE* new_f = fopen(file_name, "wb");
	if (new_f == NULL) {
		perror("Can't open file");
		exit(1);
	}

	memset(buffer_wr, 0, BUFFERS_LEN);
	memset(buffer_stop, 0, BUFFERS_FILE_DATA_LEN);
	memcpy(buffer_stop, "STOOOP", 6);

	int num_of_pack_stored = 0;

	//Recieve file
	while (1) {
		//Check if packet is in received packets array
		check_packet_in_received_packets(received_packets, &pack_num, &num_of_pack_stored, new_f);
		printf("Number of stored packets: %i\n", num_of_pack_stored);
		printf("Receiving...\n");
		//Received packets
		if (recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen) == SOCKET_ERROR) {
			printf("Socket error!\n");
			getchar();
			return 1;
		}
		int decoded_pack_num = to_int(buffer_rx[0], buffer_rx[1], buffer_rx[2], buffer_rx[3]);
		printf("Received packet with number: %i\n", decoded_pack_num);
		int decoded_data_size = to_int(buffer_rx[4], buffer_rx[5], buffer_rx[6], buffer_rx[7]);
		unsigned long decoded_crc = to_int(buffer_rx[1020], buffer_rx[1021], buffer_rx[1022], buffer_rx[1023]);
		// Get CRC
		unsigned long crc_value = get_crc(buffer_rx);
		if (decoded_crc != crc_value) {
			printf("CRC differs\n");
			//Send negative ack
			make_negative_ack(decoded_pack_num, ack_buffer);
			sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
			continue;
		}
		//Send positive ack
		make_positive_ack(decoded_pack_num, ack_buffer);
		sendto(socketS, ack_buffer, sizeof(ack_buffer), 0, (sockaddr*)&addrDest, sizeof(addrDest));
		printf("Sending packet with number %i, crc codes are same\n", to_int(ack_buffer[0], ack_buffer[1], ack_buffer[2], ack_buffer[3]));
		if (strcmp(buffer_rx + 8, buffer_stop) == 0) {
			break;
		}
		printf("DECODED PACKET NUMBER: %i\n", decoded_pack_num);
		printf("PACKET NUMBER: %i\n", pack_num);
		if (decoded_pack_num == pack_num) {
			printf("Writing to file\n");
			fwrite(buffer_rx + 8, 1, decoded_data_size, new_f);
			pack_num++;
		}
		else if (decoded_pack_num > pack_num) {
			if (check_if_decoded_num_is_in_array(received_packets, decoded_pack_num) == true) {
				continue;
			}
			//Writing to received packets array
			memset(received_packets[(decoded_pack_num - 3) % WINDOW_SIZE].buffer, 0, BUFFERS_LEN);
			memcpy(received_packets[(decoded_pack_num - 3) % WINDOW_SIZE].buffer, buffer_rx, BUFFERS_LEN);
			received_packets[(decoded_pack_num - 3) % WINDOW_SIZE].is_empty = false;
			num_of_pack_stored++;
		}

	}

	closesocket(socketS);
	fclose(new_f);

	//Calculate hash and compare
	uint8_t hash_current[HASH_LEN];
	uint8_t hash_received[HASH_LEN];
	memcpy(hash_received, hash_received_buffer, HASH_LEN);
	calculate_current_hash(file_name, hash_current);
	check_hash(hash_current, hash_received);

#endif
	return 0;
}