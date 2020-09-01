/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <string> //added
#include <iostream>
#include <E/E_TimeUtil.hpp>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{
	std::list<Socket*>::iterator unbind_iter = this->unbinded_sockets.begin();
	std::list<Socket*>::iterator bind_iter = this->binded_sockets.begin();

	if(!this->unbinded_sockets.empty())
	{
		for(; unbind_iter != this->unbinded_sockets.end() ;unbind_iter++)
		{
			// delete (*unbind_iter)->userinfo;
			delete (*unbind_iter);
		}
	}
	this->unbinded_sockets.clear();

	if(!this->binded_sockets.empty())
	{
		for(; bind_iter != this->binded_sockets.end() ;bind_iter++)
		{
			// delete (*bind_iter)->userinfo;
			delete (*bind_iter);
		}
	}
	this->binded_sockets.clear();
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{
	
}

void PacketManager::getSrcIpAddr(unsigned long *ip_addr){
	this->target_packet->readData(14+12, ip_addr, 4);
}

void PacketManager::getDestIpAddr(unsigned long *ip_addr){
	this->target_packet->readData(14+16, ip_addr, 4);
}

void PacketManager::setSrcIpAddr(unsigned long *ip_addr){
	this->target_packet->writeData(14+12, ip_addr, 4);
}

void PacketManager::setDestIpAddr(unsigned long *ip_addr){
	this->target_packet->writeData(14+16, ip_addr, 4);
}

void PacketManager::getSrcPort(uint16_t *port_num){
	this->target_packet->readData(14+20, port_num, 2);
}

void PacketManager::getDestPort(uint16_t *port_num){
	this->target_packet->readData(14+22, port_num, 2);
}

void PacketManager::setSrcPort(uint16_t *port_num){
	this->target_packet->writeData(14+20, port_num, 2);
}

void PacketManager::setDestPort(uint16_t *port_num){
	this->target_packet->writeData(14+22, port_num, 2);
}

void PacketManager::getFlag(uint16_t *buf){
	this->target_packet->readData(14+20+12, buf, 4);
}

void PacketManager::setFlag(int syn, int ack, int fin){
	uint16_t flag=0;
	flag = flag | (fin);
	flag = flag | (syn<<1);
	flag = flag | (ack<<4);
	flag = flag | (5<<12);
	flag=htons(flag);
	this->target_packet->writeData(14+20+12, &flag, 2);
}

void PacketManager::getPayload(uint8_t *buf, size_t length){
	this->target_packet->readData(14+20+20, buf, length);
}

void PacketManager::setPayload(uint8_t *buf, size_t length){
	this->target_packet->writeData(14+20+20, buf, length);
	this->paylaod_length = length;
}

void PacketManager::getSeqnum(unsigned long *seq_num){
	this->target_packet->readData(14+24, seq_num, 4);
}

void PacketManager::getAcknum(unsigned long *ack_num){
	this->target_packet->readData(14+28, ack_num, 4);
}

void PacketManager::setSeqnum(unsigned long *seq_num){
	this->target_packet->writeData(14+24, seq_num, 4);
}

void PacketManager::setAcknum(unsigned long *ack_num){
	this->target_packet->writeData(14+28, ack_num, 4);
}

void PacketManager::setChecksum(void)
{ //should be conducted at last
	uint32_t src_ip_address = 0;
	uint32_t dest_ip_address =0;
	size_t length = this->paylaod_length;
	uint8_t *tcp_seg;
	tcp_seg = new uint8_t[20+length];
	this->target_packet->readData(14+20, tcp_seg, 20+length);
	this->target_packet->readData(14+12, &src_ip_address, 4);
	this->target_packet->readData(14+16, &dest_ip_address, 4);
	uint16_t checksum = NetworkUtil::tcp_sum(src_ip_address, dest_ip_address, tcp_seg, 20+length);
	checksum = htons(~checksum);
	this->target_packet->writeData(14+20+16, &checksum, 2);
	delete tcp_seg;
}

void PacketManager::getChecksum(uint16_t *checksum)
{ //should be conducted at last
	this->target_packet->readData(14+20+16, checksum, 2);
}

void PacketManager::getWindowSize(uint16_t *window_size){
	this->target_packet->readData(14+34, window_size, 2);
}

void PacketManager::setWindowSize(uint16_t *window_size){
	this->target_packet->writeData(14+34, window_size, 2);
}

void PacketManager::getIpLength(uint16_t *ip_size)
{
	this->target_packet->readData(14+2, ip_size, 2);
}

size_t TCPAssignment::read_internal_receiver_buffer(Socket *socket, uint8_t *target_buf, InternalBuffer *data_buf, int count)
{
	int total_read_data_size = 0;

	// size_t remaining_to_read_data_size = data_buf->allocated_buffer_size - (data_buf->cursor - data_buf->payloads.begin()->second.start_num);
	// int remaining_to_read_data_size = data_buf->allocated_buffer_size;
	// int remaining_to_read_data_size =data_buf->allocated_buffer_size - (data_buf->cursor - data_buf->payloads.begin()->second.start_num);
	int remaining_to_read_data_size = data_buf->consecutive_cursor - data_buf->cursor;
	// printf("consecutive cursor value is %d, cursor value is %d\n", data_buf->consecutive_cursor, data_buf->cursor);

	if(remaining_to_read_data_size > count)
		total_read_data_size = count; // read only some of the payload
	else
	{
		//total_read_data_size = data_buf->allocated_buffer_size; // read all payload in the receiver buffer
		total_read_data_size = remaining_to_read_data_size;
	}

	if(total_read_data_size == 0)
	{
		// // std::cout<<"total reading data size is 0. It should be filtered in read syscall and packet arrived\n";
		// printf("total reading data size is 0. Consecuvive and normal cursor value is %d\n", data_buf->consecutive_cursor );
		// for(auto temp_iter = data_buf->payloads.begin(); temp_iter != data_buf->payloads.end(); temp_iter++)
		// {
		// 	printf("Each payload in internal receiver buffer's star num is %d, end num is %d\n",temp_iter->second.start_num, temp_iter->second.end_num);
		// }

		// send ack to make fast retransmit
		// it doesn't works. We have to block the read syscall in this case
		// unsigned long new_ack_num = (unsigned long)socket->receiver_buffer->consecutive_cursor;
		// socket->ack_num = new_ack_num;
		// // unsigned long new_seq_num = (unsigned long)socket->seq_num;
		// // socket->seq_num = new_seq_num;
		// unsigned long new_seq_num = 3131313;
		// unsigned long src_ip = socket->local_ip_address;
		// unsigned long dest_ip = socket->remote_ip_address;
		// uint16_t src_port = socket->local_port_num;
		// uint16_t dest_port = socket->remote_port_num;
		// this->send_packet(socket, &src_ip, &dest_ip, &src_port, &dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
		return 0;
	}

	bool found_last_consecutive_payload = false;
	std::map<int, struct packet_unit_payload>::iterator last_consecutive_payload_iter;
	struct packet_unit_payload last_consecutive_payload;
	for(auto payload_data_iter = data_buf->payloads.begin(); payload_data_iter != data_buf->payloads.end(); payload_data_iter++)
	{
		if(payload_data_iter->second.end_num + 1 == data_buf->consecutive_cursor)
		{
			found_last_consecutive_payload = true;
			last_consecutive_payload_iter = payload_data_iter;
			last_consecutive_payload_iter++;
			last_consecutive_payload = payload_data_iter->second;
			break;
		}
	}

	if(!found_last_consecutive_payload)
	{
		if(data_buf->allocated_buffer_size == 0)
		{
			if(!data_buf->payloads.empty())
			{
				printf("Allocated buffer size is 0, but payloads is not empty in reading\n");
				return -1;
			}
			printf("It should be fitlered by total_read_data_size ==0 in reading. why this occurs?\n");
			return -1;
		}
		else
		{
			if(!data_buf->payloads.empty())
			{
				printf("Allocated buffer size is not 0, but payloads is empty in reading\n");
				return -1;
			}
			printf("Internal receiver buffer's payloads is not empty but there is no corresponding payloads whose end_num + 1 == consecuitve cursor \n");
			return -1;
		}
	}

	// printf("Total reading data size is : %d\n", total_read_data_size);

	bool found_corr_payload_data = false;
	bool cursor_between_case = false;
	struct packet_unit_payload initial_payload;
	std::map<int, struct packet_unit_payload>::iterator initial_payload_iter;
	if (data_buf->payloads.find(data_buf->cursor) != data_buf->payloads.end())
	{
		found_corr_payload_data = true;
		initial_payload = data_buf->payloads.find(data_buf->cursor)->second;
		initial_payload_iter = data_buf->payloads.find(data_buf->cursor);
	}

	if(!found_corr_payload_data)
	{
		for(auto payload_data_iter = data_buf->payloads.begin(); payload_data_iter != last_consecutive_payload_iter; payload_data_iter++)
		{
			if((*payload_data_iter).second.start_num < data_buf->cursor && (*payload_data_iter).second.end_num >= data_buf->cursor)
			{
				found_corr_payload_data = true;
				cursor_between_case = true;
				initial_payload = payload_data_iter->second;
				initial_payload_iter = payload_data_iter;
				break;
			}
		}
	}

	if(!found_corr_payload_data)
	{
		std::cout<<"cursor data is : "<<data_buf->cursor<<"\n";
		printf("consecutive cursor data is : %d\n", data_buf->consecutive_cursor);
		for(auto payload_data_iter = data_buf->payloads.begin(); payload_data_iter != data_buf->payloads.end(); payload_data_iter++)
		{
			// std::cout<<"each payload start num is : "<<payload_data_iter->first<<"\n";
			printf("each payload start num is : %d\n", payload_data_iter->second.start_num);
			if((*payload_data_iter).second.start_num < data_buf->cursor)
				printf("Comparison: cursor is bigger than each payload start num\n");
			// std::cout<<'each payload end num is : '<<payload_data_iter->second.end_num<<"\n";
			printf("each payload end num is : %d\n", payload_data_iter->second.end_num);
			if((*payload_data_iter).second.end_num >= data_buf->cursor)
				printf("Comparison: cursor is smaller or equal than each payload end num\n");
		}
		std::cout<<"Can't find initial payload in receiver buffer\n";

		// send ack to make fast retransmit
		unsigned long new_ack_num = (unsigned long)socket->receiver_buffer->consecutive_cursor;
		socket->ack_num = new_ack_num;
		unsigned long new_seq_num = (unsigned long)socket->seq_num;
		socket->seq_num = new_seq_num;
		unsigned long src_ip = socket->local_ip_address;
		unsigned long dest_ip = socket->remote_ip_address;
		uint16_t src_port = socket->local_port_num;
		uint16_t dest_port = socket->remote_port_num;
		this->send_packet(socket, &src_ip, &dest_ip, &src_port, &dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);

		return -1;
		// return 0;
	}

	if(initial_payload.start_num > last_consecutive_payload.start_num)
	{
		std::cout<<"Initial payload is in right side of last consecutie payload. Somethings wrong\n";
		return -1;
	}

	// Read data
	// size_t read_data_sum = 0;
	int read_data_sum = 0;

	if(cursor_between_case)
	{
		// first, read initial payload
		// std::cout<<"between case!\n";
		int initial_read_size = 0;
		bool should_finish = false;
		bool should_remove_payload = false;
		if(initial_payload.start_num + initial_payload.size - data_buf->cursor < total_read_data_size)
		{
			// std::cout<<"should not finish!\n";
			// printf("total_read_data_size is %d\n", total_read_data_size);
			initial_read_size = initial_payload.start_num + initial_payload.size - data_buf->cursor;
		}

		else if (initial_payload.start_num + initial_payload.size - data_buf->cursor == total_read_data_size)
		{
			// std::cout<<"should finish 1!\n";
			initial_read_size = total_read_data_size;
			should_finish = true;
			should_remove_payload = true;
		}
		
		else
		{
			// std::cout<<"should finish 2!\n";
			initial_read_size = total_read_data_size;
			should_finish = true;
		}
			
		memcpy(target_buf, (char *)initial_payload.payload + data_buf->cursor - initial_payload.start_num, initial_read_size);

		read_data_sum += initial_read_size;
		// printf("prev_cursor is %d\n", data_buf->cursor);
		data_buf->cursor += initial_read_size;
		// printf("modified_cursor is %d\n", data_buf->cursor);

		if(should_finish && !should_remove_payload)
		{
			return total_read_data_size;
		}
		else if(should_finish && should_remove_payload)
		{
			data_buf->remained_buffer_size += initial_payload.size; // since initial "packet unit payload" will be removed from internal_receiver_buffer
			data_buf->allocated_buffer_size -= initial_payload.size;
			// printf("Erased payload whose start num is %d, end num is %d in cursor between case reading only one payload\n",initial_payload.start_num,initial_payload.end_num);
			data_buf->payloads.erase(initial_payload.start_num);
			return total_read_data_size;
		}

		data_buf->remained_buffer_size += initial_payload.size; // since initial "packet unit payload" will be removed from internal_receiver_buffer
		data_buf->allocated_buffer_size -= initial_payload.size;
	}

	if (data_buf->payloads.find(data_buf->cursor) == data_buf->payloads.end())
	{
		std::cout<<"In reading, cursor_between_case, cursor moved to wierd place. Something's wrong\n";
		// printf("cursor data is : %d\n", data_buf->cursor);
		// for(auto payload_data_iter = data_buf->payloads.begin(); payload_data_iter != data_buf->payloads.end(); payload_data_iter++)
		// {
		// 	// std::cout<<"each payload start num is : "<<payload_data_iter->first<<"\n";
		// 	printf("each payload start num is : %d\n", payload_data_iter->second.start_num);
		// 	if((*payload_data_iter).second.start_num < data_buf->cursor)
		// 		printf("Comparison: cursor is bigger than each payload start num\n");
		// 	// std::cout<<'each payload end num is : '<<payload_data_iter->second.end_num<<"\n";
		// 	printf("each payload end num is : %d\n", payload_data_iter->second.end_num);
		// 	if((*payload_data_iter).second.end_num >= data_buf->cursor)
		// 		printf("Comparison: cursor is smaller or equal than each payload end num\n");
		// }
		return -1;
	}

	// we should read more payloads	
	//int previous_expected_start_num = found_initial_payload.start_num + found_initial_payload.size;
	std::map<int, struct packet_unit_payload>::iterator final_payload_iter;
	bool found_final_payload = false;
	bool min_read_case = false;
	int additional_payload_count = 0;
	for(auto payload_data_iter = data_buf->payloads.find(data_buf->cursor); payload_data_iter != last_consecutive_payload_iter; payload_data_iter++)
	{
		//std::cout<<"cursor on start case!\n";
		struct packet_unit_payload each_payload = payload_data_iter->second;
		final_payload_iter = payload_data_iter;
		additional_payload_count++;
		if(read_data_sum + each_payload.size > total_read_data_size)
		{
			// finish reading or read as possbie range (read just part of packet unit payload)
			// std::cout<<"reading part for last case\n";
			size_t reading_byte = total_read_data_size - read_data_sum;
			memcpy((char *)target_buf+read_data_sum, (char *)each_payload.payload, reading_byte);
			read_data_sum += reading_byte;
			// printf("prev_cursor is %d\n", data_buf->cursor);
			data_buf->cursor += reading_byte;
			// printf("modified_cursor is %d\n", data_buf->cursor);


			// data_buf->remained_buffer_size += reading_byte;
			
			found_final_payload = true;
			final_payload_iter--;
			if(additional_payload_count == 1)
			{
				min_read_case = true;
				break;
			}
			break;
		}
		else if(read_data_sum + each_payload.size == total_read_data_size)
		{
			// read this payload for last and finish it
			// std::cout<<"reading whole for last case\n";
			// size_t reading_byte = each_payload.size;
			int reading_byte = each_payload.size;
			// printf("read_data_sum was %d, reading_byte is %d\n",read_data_sum,reading_byte);
			// memcpy((char *)target_buf+read_data_sum, (char *)each_payload.payload, reading_byte);
			// memset((uint8_t *)target_buf+read_data_sum, 0, static_cast<size_t>(reading_byte));
			memcpy((uint8_t *)target_buf+read_data_sum, (uint8_t *)each_payload.payload, static_cast<size_t>(reading_byte));
			read_data_sum += reading_byte;
			data_buf->cursor += reading_byte;
			data_buf->remained_buffer_size += reading_byte;
			data_buf->allocated_buffer_size -= reading_byte;
			found_final_payload = true;

			// delete each_payload.payload;

			break;
		}
		else
		{
			// we shuold read more payloads
			// std::cout<<"reading whole for interim case\n";
			size_t reading_byte = each_payload.size;
			memcpy((char *)target_buf+read_data_sum, (char *)each_payload.payload, reading_byte);
			read_data_sum += reading_byte;
			data_buf->cursor += reading_byte;
			data_buf->remained_buffer_size += reading_byte;
			data_buf->allocated_buffer_size -= reading_byte;
		}
	}
	
	if(total_read_data_size != read_data_sum)
	{
		std::cout<<"somethings wrong in reading algorithm. Readed bytes and bytes to be readed doesn't match \n";
		return -1;
	}

	if(!found_final_payload)
	{
		std::cout<<"somethings wrong in reading algorithm. It tries to read larger data than buffer stored data \n";
		return -1;		
	}

	// we read all bytes to read. now we have to remove read payloads from the internal receiver buffer, and manipulate the size element
	// final_payload_iter++;
	if(min_read_case && !cursor_between_case)
	{
		return total_read_data_size;
	}
	else
	{
		// printf("Erased payloads first element's start num is %d & end num is %d, last element's start num is %d & end num is %d in reading multiple ones\n",initial_payload.start_num,initial_payload.end_num,final_payload_iter->second.start_num,final_payload_iter->second.end_num);
		// if(cursor_between_case)
		// 	printf("also it was cursor between case.\n");
		// else
		// 	printf("it was not cursor between case\n");
		// printf("cursor is now %d, and consecutive cursor is now %d\n", data_buf->cursor, data_buf->consecutive_cursor);
		
		final_payload_iter++;
		data_buf->payloads.erase(initial_payload_iter, final_payload_iter);
		//data_buf->remained_buffer_size += total_read_data_size;
		//data_buf->allocated_buffer_size -= total_read_data_size;
		//assert(data_buf->remained_buffer_size + data_buf->allocated_buffer_size == data_buf->total_size);
		return total_read_data_size;
	}
}

size_t save_internal_sender_buffer(void *data_buf, InternalBuffer *target_buf, size_t size)
{
	size_t total_copy_data_size = 0;

	// if(target_buf->remained_buffer_size < 0)
	// {
	// 	// Now, I just made it to not save data when remained buffer size is smaller than 0
	// 	// However, maybe I should just let them be saved, and controll only sending the data
	// 	// it means, cwnd cares not the size of internal sender buffer, but only how many datas are "sent"
	// 	// printf("remained buffer size is minus, didn't save data\n");
	// 	return 0;
	// }

	// size bytes should be copied
	if(target_buf->remained_buffer_size > size)
		total_copy_data_size = size;
	else
		total_copy_data_size = target_buf->remained_buffer_size;

	if (total_copy_data_size == 0)
		return 0;
	
	//printf("remaiend_sender_buffer_size is %d\n", target_buf->remained_buffer_size);
	target_buf->remained_buffer_size -= total_copy_data_size;
	target_buf->allocated_buffer_size += total_copy_data_size;

	int whole_packet_num = total_copy_data_size/512;
	int remian_packet_size = total_copy_data_size%512;
	int whole_payload_start_from = 0;
	if (target_buf->initial == true)
	{
		whole_payload_start_from = target_buf->initial_start_num;
		target_buf->initial = false;
	}
	else
	{
		if(target_buf->payloads.empty())
		{
			// printf("sender buffer is empty but tried to access rbegin\n");
			whole_payload_start_from = target_buf->cursor;
		}
		else
		{
			whole_payload_start_from = target_buf->payloads.rbegin()->second.end_num + 1;
		}
	}
		
	

	for (int i=0; i<whole_packet_num; i++)
	{
		void *payload_buf = (char *)malloc(512);
		memcpy(payload_buf, data_buf+(i*512) ,512);
		struct packet_unit_payload each_payload;
		each_payload.start_num = whole_payload_start_from + i*512;
		each_payload.size = 512;
		each_payload.end_num = each_payload.start_num + each_payload.size - 1;
		each_payload.payload = payload_buf;
		(target_buf->payloads)[each_payload.start_num] = each_payload;
	}

	if(remian_packet_size != 0)
	{
		void *payload_buf = (char *)malloc(remian_packet_size);
		memcpy(payload_buf, data_buf+(whole_packet_num*512) ,remian_packet_size);
		struct packet_unit_payload each_payload;
		each_payload.start_num = whole_payload_start_from + whole_packet_num*512;
		each_payload.size = remian_packet_size;
		each_payload.end_num = each_payload.start_num + each_payload.size - 1;
		each_payload.payload = payload_buf;
		(target_buf->payloads)[each_payload.start_num] = each_payload;
	}
	
	return total_copy_data_size;
}

int min(int a, int b)
{
	if(a<=b)
	{
		return a;
	}
	else
	{
		return b;
	}
}

void TCPAssignment::send_data(Socket *socket)
{
	unsigned long src_ip = socket->local_ip_address;
	unsigned long dest_ip = socket->remote_ip_address;
	uint16_t src_port = socket->local_port_num;
	uint16_t dest_port = socket->remote_port_num;

	// From certain phases of closing states, it should block sending data.
	// if(socket->state == FIN_WAIT_1 || socket->state == FIN_WAIT_2 || socket->state == TIMED_WAIT || socket->state == LAST_ACK)
	// 	return;

	// if(socket->sender_buffer->remained_buffer_size < 0)
	// {
	// 	// Now, I just made it to not send data when remained buffer size is smaller than 0
	// 	// However, maybe I should send if (payloads's sizes sum starting form payload whichinclude cursor) ~ < first element's start_num + total_size + remained_buffer_size - cursor
	// 	// it means, downward limit was target_rwnd before, but it maybe has to be min(target_rwnd, first element's start_num + total_size + remained_buffer_size - cursor )
	// 	// printf("remained buffer size is minus, didn't send data\n");
	// 	return;
	// }

	int total_sending_bytes = 0;
	int total_sending_packet_num = 0;
	bool send_all_payloads_in_buffer = false;
	
	auto starting_payload_iter = (socket->sender_buffer->payloads).find(socket->sender_buffer->cursor);
	if((socket->sender_buffer->payloads).find(socket->sender_buffer->cursor) == (socket->sender_buffer->payloads).end())
	{
		// printf("there is no matching seq_num payload in sending_buffer\n");
		return;
	}

	// Don't send data if all sent packet is acked until cursor located packet
	// if(socket->sender_buffer->payloads.begin()->first < socket->sender_buffer->cursor)
	// {
	// 	//std::cout<<"Sent data is not all acked yet, pause sending data\n";
	// 	return;
	// }

	int sent_but_unacked_bytes = socket->sender_buffer->cursor - socket->sender_buffer->payloads.begin()->first;
	if(sent_but_unacked_bytes < 0)
	{
		printf("cursor is smaller than first elemenent's start num in sending data. Somethings wrong\n");
		return;
	}
	int downward_limit = min(socket->sender_buffer->allocated_buffer_size - sent_but_unacked_bytes, min(socket->sender_buffer->cwnd, static_cast<int>(socket->target_rwnd)));
	
	if(downward_limit == socket->sender_buffer->allocated_buffer_size - sent_but_unacked_bytes)
	{
		send_all_payloads_in_buffer = true;
		total_sending_bytes = socket->sender_buffer->allocated_buffer_size - sent_but_unacked_bytes;
	}
	else
	{
		// printf("receiver's rwnd is not enough to send all data in internal sender buffer, it's size is %d\n",socket->target_rwnd);
		bool found_last_payload = false;
		int maximum_sending_bytes = downward_limit;
		// printf("starting_payload_iter start_num is %d\n", starting_payload_iter->second.start_num);
		for(auto it = starting_payload_iter; it != socket->sender_buffer->payloads.end(); it++)
		{
			if(total_sending_bytes + it->second.size < maximum_sending_bytes)
			{
				total_sending_bytes += it->second.size;
				total_sending_packet_num++;
			}
			else if(total_sending_bytes + it->second.size == maximum_sending_bytes)
			{
				total_sending_bytes += it->second.size;
				total_sending_packet_num++;
				found_last_payload = true;
				break;
			}
			else
			{
				found_last_payload = true;
				break;
			}
		}

		if (!found_last_payload)
		{
			printf("Something's wrong in counting sending bytes! 1\n");
			return;
		}

		if(total_sending_packet_num == 0)
		{
			// printf("Impossible to send by flow control & congestion control\n");
			return;
		}
		// printf("total_sending_bytes is %d\n",total_sending_bytes);
	}

	int sent_payload_count = 0;
	size_t final_updating_seq_num = 0;
	// size_t expected_receiver_window_size = socket->target_rwnd; //#1
	std::map<int, struct packet_unit_payload>::iterator last_paylaod_iter;
	for(auto it = starting_payload_iter; it != socket->sender_buffer->payloads.end(); it++) // it++?
	{		
		if (!send_all_payloads_in_buffer)
		{
			if(sent_payload_count >= total_sending_packet_num)
				break;
			// else
			// 	sent_payload_count++;
		}

		sent_payload_count++;
		last_paylaod_iter = it;

		struct packet_unit_payload each_payload_data = it->second;

		// Should send data(payload, ack) packet
		unsigned long new_ack_num = socket->ack_num;
		unsigned long new_seq_num = each_payload_data.start_num;
		socket->seq_num = new_seq_num;
		//final_updating_seq_num = new_seq_num + each_payload_data.size;
		final_updating_seq_num = each_payload_data.end_num + 1;
		//corr_conn_socket->sender_buffer->cursor = new_seq_num;
		socket->sender_buffer->cursor += each_payload_data.size; // update cursor

		int ip_header_size = 20;
		int tcp_header_size = 20;
		int payload_length = each_payload_data.size;
		Packet *data_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
		PacketManager *data_packet_manager = new PacketManager(data_packet);
		data_packet_manager->setSrcIpAddr(&src_ip);
		data_packet_manager->setSrcPort(&src_port);
		data_packet_manager->setDestIpAddr(&dest_ip);
		data_packet_manager->setDestPort(&dest_port);
		new_seq_num = htonl(new_seq_num);
		data_packet_manager->setSeqnum(&new_seq_num);
		new_ack_num = htonl(new_ack_num);
		data_packet_manager->setAcknum(&new_ack_num);
		uint16_t window_size = htons(socket->receiver_buffer->remained_buffer_size);
		data_packet_manager->setWindowSize(&window_size);		
		data_packet_manager->setFlag(0, 1, 0);
		data_packet_manager->setPayload((uint8_t*)each_payload_data.payload ,each_payload_data.size);
		data_packet_manager->setChecksum();
		
		// should set data packet's timer
		Packet *clone_sent_packet = this->clonePacket(data_packet);
		set_data_packet_timer(socket, clone_sent_packet, &each_payload_data, each_payload_data.start_num);
	
		this->sendPacket("IPv4", data_packet);
		delete data_packet_manager;

		/*
		// update internal_sender_buffer's size elements
		socket->sender_buffer->remained_buffer_size += each_payload_data.size;
		socket->sender_buffer->allocated_buffer_size -= each_payload_data.size;
		*/

		// // store expected_target_rwnd //#1
		// expected_receiver_window_size -= each_payload_data.size;
		// each_payload_data.expected_receiver_window_size = expected_receiver_window_size;
	}

	// update unapplied last sequence number to socket
	socket->seq_num = final_updating_seq_num;

	return;
}

void TCPAssignment::set_system_packet_timer(Socket *manager_socket, Packet *clone_sent_packet, packet_timer_category category)
{
	// Set packet timer
	struct close_timer_info *null_cti = NULL;
	TimerInfo *payload = new TimerInfo(manager_socket, clone_sent_packet, category, true, null_cti);
	UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(100, TimeUtil::MSEC));

	struct packet_timer_list_elem p_t_l_elem;
	p_t_l_elem.category = category;
	p_t_l_elem.timer_id = timer_id;
	//p_t_l_elem.payload = payload;
	// this->estab_close_timers.push_back(p_t_l_elem);
	manager_socket->estab_close_timers[category] = p_t_l_elem;
}

bool TCPAssignment::remove_system_packet_timer(Socket *manager_socket, packet_timer_category category)
{
	//first check whether timer of category exists or not
	if(manager_socket->estab_close_timers.find(category) == manager_socket->estab_close_timers.end())
	{
		// std::cout<<"There are no such timers in estab_close_timers list.\n"; #3
		return false;
	}
	struct packet_timer_list_elem timer_elem = manager_socket->estab_close_timers.find(category)->second;
	this->cancelTimer(timer_elem.timer_id);

	//delete timer_elem.payload;
	manager_socket->estab_close_timers.erase(category);
	return true;
}

void TCPAssignment::set_data_packet_timer(Socket *manager_socket, Packet *clone_sent_packet, struct packet_unit_payload *packet_payload_data, int seq_num)
{
	// Set data packet timer
	struct close_timer_info *null_cti = NULL;
	TimerInfo *payload = new TimerInfo(manager_socket, clone_sent_packet, DATA_SEQ, true, null_cti);
	payload->corr_payload = packet_payload_data;
	payload->data_packet_seq_num = seq_num;
	UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(100, TimeUtil::MSEC));

	struct packet_timer_list_elem data_timer;
	data_timer.category = DATA_SEQ;
	data_timer.timer_id = timer_id;
	data_timer.data_packet = clone_sent_packet;
	data_timer.data_packet_payload = packet_payload_data;
	data_timer.seq_num = seq_num;
	manager_socket->data_timers[seq_num] = data_timer;
}

bool TCPAssignment::remove_data_packet_timer(Socket *manager_socket, int seq_num)
{
	// first check whether corresponding seq_num data packet's timer exists or not
	if(manager_socket->data_timers.find(seq_num) == manager_socket->data_timers.end())
	{
		std::cout<<"There are no such timers in data_timers list.\n";
		return false;
	}
	struct packet_timer_list_elem timer_elem = manager_socket->data_timers.find(seq_num)->second;
	this->cancelTimer(timer_elem.timer_id);

	//delete timer_elem.payload;
	manager_socket->data_timers.erase(seq_num);
	return true;
}

void TCPAssignment::data_ack_process(unsigned long ack_num_h, Socket *socket, uint16_t new_rwnd, int payload_length)
{
	// Remove data from internal sender buffer
	std::map<int, struct packet_unit_payload>::iterator payload_data_iter;
	struct packet_unit_payload found_payload;
	bool found_corr_payload_data = false;
	int acked_payload_num = 0;
	int acked_total_data_length = 0;
	std::map<int, struct packet_unit_payload>::iterator last_payload_iter;
	for(payload_data_iter = socket->sender_buffer->payloads.begin(); payload_data_iter != socket->sender_buffer->payloads.end(); payload_data_iter++)
	{
		acked_payload_num++;
		acked_total_data_length += payload_data_iter->second.size;
		if((*payload_data_iter).second.start_num + (*payload_data_iter).second.size == ack_num_h )
		{
			found_corr_payload_data = true;
			found_payload = (*payload_data_iter).second;
			last_payload_iter = payload_data_iter;
			break;
		}
	}

	// update rwnd value
	socket->target_rwnd = new_rwnd;

	if(!found_corr_payload_data)
	{
		if(payload_length < 0)
		{
			std::cout<<"payload length is smaller than 0!!!\n";
			return;
		}
		else if(payload_length == 0)
		{
			// If received packet's payloads size is 0, then
			// It means it received ack packet for sent packet but there is no such data in internal sender buffer
			// So it might be retransmission of ack packet

			// (*payload_data_iter).second.start_num + (*payload_data_iter).second.size == ack_num_h 
			// ack_num_h - (*payload_data_iter).second.size == (*payload_data_iter).second.start_num
			if( socket->sender_buffer->payloads.begin()->first > ack_num_h )
			{
				std::cout<<"Seems to received ack of data packet and no such info in internal sender buffer, the retransmission, but ack_num is smaller than first one\n";
				return;
			}
			else if(socket->sender_buffer->payloads.begin()->first == ack_num_h)
			{
				// received ack_num is equal with first one's start num, so it should be ack retransmission
				// if there is no ack_num in retransmit checker, then this is ther second retransmission
				if(socket->fast_retransmit_checker.find(ack_num_h) == socket->fast_retransmit_checker.end())
				{
					// established_socket->fast_retransmit_checker.insert(ack_num_h);
					socket->fast_retransmit_checker[ack_num_h] = 2;
					// std::cout<<"Second retransmission\n";
					return;
				}
				// if there is ack_num in retransmit checker, then this is third retransmission. Conduct fast retransmission
				else
				{
					socket->fast_retransmit_checker[ack_num_h] += 1;

					// # 4 maybe we should change here. To retransmit not once.
					if(socket->fast_retransmit_checker.find(ack_num_h)->second > 3)
					{
						// retransmit just once

						// congestion control
						if(socket->cg_state == FAST_RECOVERY)
						{
							// change cwnd. cwnd = 1 MSSS
							socket->sender_buffer->cwnd += MSS;
							if(socket->sender_buffer->cwnd == 0)
								printf("0 case 1\n");

							// send new data if possible
							this->send_data(socket);
						}

						return;
					}
					
					// printf("Fast retransmission of %d\n", ack_num_h);
					// printf("Checker value is  %d\n", socket->fast_retransmit_checker[ack_num_h]);

					if (socket->data_timers.find(ack_num_h) == socket->data_timers.end())
					{
						std::cout<<"There's no sent packet data with correspionding seq_num in data_timers list. Something's wrong 1\n";
						printf("Then, is data_timers list is empty?? : %d\n",socket->data_timers.empty());
						for(auto temp_iter=socket->sender_buffer->payloads.begin(); temp_iter!=socket->sender_buffer->payloads.end(); temp_iter++)
						{
							printf("paylaod's element's start_num is %d, end_num is %d!!!\n", temp_iter->second.start_num,temp_iter->second.end_num);
						}
						this->send_data(socket);
						return;
					}

					else if (socket->data_timers.find(ack_num_h) != socket->data_timers.begin())
					{
						std::cout<<"There's sent packet data with corresponding in data_timers list but it's not first element. Something's wrong\n";
						return;
					}
					
					// reset fast retransmission checker
					// established_socket->fast_retransmit_checker.clear();
					// established_socket->fast_retransmit_checker.erase(ack_num_h);

					// congestion control
					if(socket->cg_state == SLOW_START)
					{
						// change ssthresh. ssthesh = cwnd/2
						socket->sender_buffer->ssthresh = socket->sender_buffer->cwnd/2;
						if(socket->sender_buffer->ssthresh == 0)
							printf("ssth 0 case 1\n");

						// change cwnd. cwnd = ssthresh + 3*MSS
						socket->sender_buffer->cwnd = socket->sender_buffer->ssthresh + 3*MSS;
						if(socket->sender_buffer->cwnd == 0)
							printf("0 case 2\n");

						// change state to fast recovery
						socket->cg_state = FAST_RECOVERY;
					}
					else if(socket->cg_state == CONGESTION_AVOIDANCE)
					{
						// change ssthresh. ssthesh = cwnd/2
						socket->sender_buffer->ssthresh = socket->sender_buffer->cwnd/2;
						if(socket->sender_buffer->ssthresh == 0)
							printf("ssth 0 case 2\n");

						// change cwnd. cwnd = ssthresh + 3*MSS
						socket->sender_buffer->cwnd = socket->sender_buffer->ssthresh + 3*MSS;
						if(socket->sender_buffer->cwnd == 0)
							printf("0 case 3\n");

						// change state to fast recovery
						socket->cg_state = FAST_RECOVERY;
					}
					else
					{
						printf("It got normal ack but socket's state is imossible weird state or FAST_RECOVRY\n");
						return;
					}

					// fast retransmission
					for(auto timer_iter = socket->data_timers.begin(); timer_iter != socket->data_timers.end(); timer_iter++)
					{
						// cancel timer
						this->cancelTimer(timer_iter->second.timer_id);

						// retrnasmit data 
						Packet *stored_packet = timer_iter->second.data_packet;
						if(stored_packet == NULL)
						{
							std::cout<<"stored data packet is NULL\n";
							return;
						}

						Packet *clone_sent_packet = this->clonePacket(stored_packet);
						this->sendPacket("IPv4", stored_packet);

						// set new data packet timer again
						struct close_timer_info *null_cti = NULL;
						TimerInfo *payload = new TimerInfo(socket, clone_sent_packet, DATA_SEQ, true, null_cti);
						payload->corr_payload = timer_iter->second.data_packet_payload;
						payload->data_packet_seq_num = timer_iter->second.seq_num;
						UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(100, TimeUtil::MSEC));

						// save newly setted timer's id and packet to send, since we cloned it because sending packet process free the packet
						timer_iter->second.timer_id = timer_id;
						timer_iter->second.data_packet = clone_sent_packet;
					}
					return;
				}
			}
			else
			{
				std::cout<<"Seems to received ack of data packet and no such info in internal sender buffer, the retransmission, but ack_num is larger than first one\n";
				return;
			}
			return;
		}
	}
	// if(!found_corr_payload_data)
	// {
	// 	for (auto temp_iter = socket->sender_buffer->payloads.begin(); temp_iter!=socket->sender_buffer->payloads.end(); temp_iter++)
	// 	{
	// 		printf("each payload's start num is %d end num is %d\n",temp_iter->second.start_num,temp_iter->second.end_num);
	// 	}
	// 	printf("Didn't find corresponding ack during data_ack_process, ack num is %d\n", ack_num_h);
	// 	return;
	// }

	// Erase fast retransmit checker element previous ones of received ack packet. Reset fast retransmit checker (dup ack count = 0)
	for(auto checker_iter = socket->fast_retransmit_checker.begin(); checker_iter != socket->fast_retransmit_checker.end();)
	{
		// if (found_payload.start_num >= *checker_iter) # 4
		if (found_payload.start_num >= checker_iter->first)
		{
			// printf("Fast retransmission checker erase case 1, seq_num is %d\n",checker_iter->first);
			checker_iter = socket->fast_retransmit_checker.erase(checker_iter);
		}
		else
		{
			checker_iter++;
		}
	}

	last_payload_iter++;
	for(payload_data_iter = socket->sender_buffer->payloads.begin(); payload_data_iter != last_payload_iter; payload_data_iter++)
	{
		// turn off the timer
		if(!remove_data_packet_timer(socket, payload_data_iter->first))
		{
			return;
		}
			
		// manipulate the buffer size elements
		if(socket->sender_buffer->remained_buffer_size + payload_data_iter->second.size <= socket->sender_buffer->total_size)
		{
			socket->sender_buffer->remained_buffer_size += payload_data_iter->second.size;
			socket->sender_buffer->allocated_buffer_size -= payload_data_iter->second.size;
			assert(socket->sender_buffer->remained_buffer_size + socket->sender_buffer->allocated_buffer_size == socket->sender_buffer->total_size);
		}
		else
		{
			printf("sender buffer remained size exceeds the total size!!");
			return;
		}

		// free the data	
		delete payload_data_iter->second.payload;
	}

	// remove data from payloads list
	socket->sender_buffer->payloads.erase(socket->sender_buffer->payloads.begin(), last_payload_iter);

	// unblock the write systemcall
	if(socket->sender_buffer->remained_buffer_size > 0)
	{
		if(!socket->blocked_syscall.empty())
		{
			//printf("blockes syscall's number is %d\n", socket->blocked_syscall.size());
			struct blocked_syscall_info blocked_syscall = socket->blocked_syscall.front();
			if(blocked_syscall.category == WRITE_SYSCALL)
			{
				//printf("it's write!\n");
				// assert(false);
				// unblock the blocked write systemcall
				size_t copied_data = save_internal_sender_buffer(blocked_syscall.buf, socket->sender_buffer, blocked_syscall.count);
				this->returnSystemCall(blocked_syscall.syscall_id, copied_data);
				socket->blocked_syscall.pop_front();
			}			
		}
	}

	// congestion control
	if(socket->cg_state == SLOW_START)
	{
		// change cwnd. cwnd = cwnd + MSS
		socket->sender_buffer->cwnd += MSS;
		if(socket->sender_buffer->cwnd == 0)
			printf("0 case 4\n");

		// check if cwnd is >= than ssthresh. If satisfies, change state to Congestion Avoidance
		if(socket->sender_buffer->cwnd >= socket->sender_buffer->ssthresh)
		{
			socket->cg_state = CONGESTION_AVOIDANCE;
		}
	}
	else if(socket->cg_state == CONGESTION_AVOIDANCE)
	{
		// change cwnd. cwnd = cwnd + MSS*(MSS/cwnd)
		// here can be dangerous since total_size is int but MSS/total_size is float
		socket->sender_buffer->cwnd += MSS * static_cast<int> (MSS/socket->sender_buffer->cwnd);
		if(socket->sender_buffer->cwnd == 0)
			printf("0 case 5\n");
	}
	else if(socket->cg_state == FAST_RECOVERY)
	{
		// change cwnd. cwnd = ssthresh
		socket->sender_buffer->cwnd = socket->sender_buffer->ssthresh;
		if(socket->sender_buffer->cwnd == 0)
			printf("0 case 6\n");

		// chage state to congestion avoidance
		socket->cg_state = CONGESTION_AVOIDANCE;

		// Since it should not send new data in this case. but i'm not sure...
		return;
	}
	else
	{
		printf("It got normal ack but socket's state is imossible weird state\n");
		return;
	}

	this->send_data(socket);
	return;
}

void TCPAssignment::send_packet(Socket *socket, unsigned long *src_ip, unsigned long *dest_ip, uint16_t *src_port, uint16_t *dest_port, unsigned long new_ack_num, unsigned long new_seq_num, int syn, int ack, int fin, bool is_data_packet, uint8_t *payload ,int payload_length)
{
	// update socket's seq_num and ack_num
	socket->ack_num = new_ack_num;
	socket->seq_num = new_seq_num;

	// Create packet
	int ip_header_size = 20;
	int tcp_header_size = 20;
	Packet *packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
	PacketManager *packet_manager = new PacketManager(packet);
	packet_manager->setSrcIpAddr(dest_ip);
	packet_manager->setSrcPort(dest_port);
	packet_manager->setDestIpAddr(src_ip);
	packet_manager->setDestPort(src_port);
	new_seq_num = htonl(new_seq_num);
	packet_manager->setSeqnum(&new_seq_num);
	new_ack_num = htonl(new_ack_num);
	packet_manager->setAcknum(&new_ack_num);
	uint16_t window_size = htons(socket->receiver_buffer->remained_buffer_size);
	packet_manager->setWindowSize(&window_size);		
	packet_manager->setFlag(syn, ack, fin);

	if (is_data_packet)
	{
		packet_manager->setPayload(payload ,payload_length);
	}

	packet_manager->setChecksum();
	this->sendPacket("IPv4", packet);
	delete packet_manager;

	return;
}

void TCPAssignment::move_consecutive_cursor(Socket *socket)
{
	if(socket->receiver_buffer->payloads.size() == 1)
	{
		// check cursor and payload's start_num is same
		// it's unconsecutive, so just let consecutive cursor be cursor
		if(socket->receiver_buffer->cursor < socket->receiver_buffer->payloads.begin()->first)
		{
			socket->receiver_buffer->consecutive_cursor = socket->receiver_buffer->cursor;
			return;
		}

		// it's consecutive so move consecutive cursor
		else if (socket->receiver_buffer->cursor == socket->receiver_buffer->payloads.begin()->first)
		{
			socket->receiver_buffer->consecutive_cursor = socket->receiver_buffer->payloads.begin()->second.end_num + 1;
			return;
		}

		else
		{
			std::cout<<"element's start num is smaller than cursor soemthings wrong\n";
			return;
		}
		return;
	}

	else if (socket->receiver_buffer->payloads.size() == 0)
	{
		std::cout<<"Tried to move consecutive cursor but receiver buffer is empty somethings wrong\n";
		return;
	}

	// receiver buffer's size is larger or equal than 2
	if(socket->receiver_buffer->cursor < socket->receiver_buffer->payloads.begin()->first)
	{
		socket->receiver_buffer->consecutive_cursor = socket->receiver_buffer->cursor;   // This might be very dangerous # 7
		return;
	}

	bool found_unconsecutive_element = false;
	auto last_payload_iter = socket->receiver_buffer->payloads.end()--;
	int initial_start_num = socket->receiver_buffer->cursor;
	for(auto paylaod_iter=socket->receiver_buffer->payloads.begin(); paylaod_iter!=last_payload_iter; paylaod_iter++)
	{
		auto next_element_iter = paylaod_iter; // dangerous
		next_element_iter++;

		// found unconsecutive element
		if(paylaod_iter->second.end_num + 1 < next_element_iter->second.start_num)
		{
			found_unconsecutive_element = true;
			socket->receiver_buffer->consecutive_cursor = paylaod_iter->second.end_num + 1;
			// printf("Consecutive cursor moved largely.\n");
			// printf("Cursor is %d, Consecutive cursor is %d\n",socket->receiver_buffer->cursor, socket->receiver_buffer->consecutive_cursor);
			// printf("It was in moving cons cursor. Payloads first element's start num is %d & end num is %d, last elemement's start_num is %d & end num is %d\n", socket->receiver_buffer->payloads.begin()->first,socket->receiver_buffer->payloads.begin()->second.end_num,socket->receiver_buffer->payloads.rbegin()->first, socket->receiver_buffer->payloads.rbegin()->second.end_num);
			break;
		}
	}

	if(!found_unconsecutive_element)
	{
		socket->receiver_buffer->consecutive_cursor = socket->receiver_buffer->payloads.rbegin()->second.end_num + 1;
	}

	return;
}

void TCPAssignment::data_process(Socket *socket, unsigned long *src_ip, unsigned long *dest_ip, uint16_t *src_port, uint16_t *dest_port, int ack_num_h, int seq_num_h, void *received_payload, int payload_length)
{
	// Check whether internal_receiver_buffer's remained space is enough
	if(socket->receiver_buffer->remained_buffer_size < payload_length)
	{
		// case flow control failed??
		return;
	}

	if(socket->receiver_buffer->payloads.find(seq_num_h) == socket->receiver_buffer->payloads.end())
	{
		// if size is enough, add(save) received paylaod into internal receiver buffer
		void *payload_buf = (char *)malloc(payload_length);
		memcpy(payload_buf, received_payload ,payload_length);
		struct packet_unit_payload each_payload;
		each_payload.start_num = seq_num_h;
		each_payload.size = payload_length;
		each_payload.end_num = each_payload.start_num + each_payload.size-1;
		each_payload.payload = payload_buf;
		(socket->receiver_buffer->payloads)[each_payload.start_num] = each_payload;

		// change the size values
		socket->receiver_buffer->remained_buffer_size -= payload_length;
		socket->receiver_buffer->allocated_buffer_size += payload_length;

		// move consecutive cursor
		this->move_consecutive_cursor(socket);

		// check the blocked read syscall
		if(!socket->blocked_syscall.empty())
		{
			struct blocked_syscall_info blocked_syscall = socket->blocked_syscall.front();
			//std::cout<<"check1\n";
			if(blocked_syscall.category == READ_SYSCALL)
			{
				// unblock the blocked read systemcall
				// check whether previous receiver buffer was empty for error checking
				//std::cout<<"check2\n";
				if(socket->receiver_buffer->allocated_buffer_size - payload_length != 0)
					{
						// Case when there is blocked read syscall but receiver buffer was not empty before receiving data packet
						// std::cout<<"when receiving data packet, remained buffer wasn't empty but read was blocked. Unconsecutive case \n";
						// return;
					}
				// std::cout<<"case 2: unblocking the read syscall in data process\n";
				size_t readed_data = read_internal_receiver_buffer(socket, (uint8_t *)blocked_syscall.buf, socket->receiver_buffer, blocked_syscall.count);

				// # 6
				if (readed_data == 0)
				{
					// std::cout<<"tried to unblock the read syscall and read it, but impossible since data is not consecutive\n";
					// return;
				}

				// printf("readed %d data from internal sender buffer at case 2 read unblocking\n", readed_data);
				else
				{
					this->returnSystemCall(blocked_syscall.syscall_id, readed_data);
					socket->blocked_syscall.pop_front();
				}
			}
		}
	}

	// send ack packet for received packet
	unsigned long new_ack_num = (unsigned long)socket->receiver_buffer->consecutive_cursor;
	socket->ack_num = new_ack_num;
	unsigned long new_seq_num = (unsigned long)ack_num_h;
	socket->seq_num = new_seq_num;
	this->send_packet(socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);

	delete received_payload;
	return;
}


// int do_fast_retransmit(Socket *socket)
// {
// 	if(socket->fast_retransmit_checker[0] == socket->fast_retransmit_checker[1] && socket->fast_retransmit_checker[1] == socket->fast_retransmit_checker[2])
// 	{
// 		return socket->fast_retransmit_checker[0] + 1;
// 	}
// 	return -1;
// }

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	int fd = this->createFileDescriptor(pid);

	Socket *socket = new Socket(pid, fd, MSS, 51200);
	//socket->pid = pid;
	this->unbinded_sockets.push_back(socket);
	this->returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	// std::cout<<"syscall_close called!!!\n";

	// 1. socket state is before ESTAB
	bool unbind_success = false;
	bool bind_success = false;
	std::list<Socket*>::iterator unbind_iter;
	std::list<Socket*>::iterator bind_iter;
	std::list<struct address_info>::iterator bind_addr_iter;
	if(!this->unbinded_sockets.empty())
	{
		for(unbind_iter=this->unbinded_sockets.begin(); unbind_iter!=this->unbinded_sockets.end(); unbind_iter++)
		{
			if((*unbind_iter)->fd == fd && (*unbind_iter)->pid == pid)
			{
				delete (*unbind_iter);
				unbind_iter = this->unbinded_sockets.erase(unbind_iter);
				unbind_success = true;
				break;
			}
		}
	}

	if(!unbind_success)
	{
		if(!this->binded_sockets.empty())
		{
			for(bind_iter=this->binded_sockets.begin(); bind_iter!= this->binded_sockets.end(); bind_iter++)
			{
				if((*bind_iter)->fd == fd  && (*bind_iter)->pid == pid)
				{
					delete (*bind_iter);
					bind_iter = this->binded_sockets.erase(bind_iter);
					bind_success = true;
					break;
				}
			}
		}

		if(!this->local_addresses.empty())
		{
			for(bind_addr_iter=this->local_addresses.begin(); bind_addr_iter != this->local_addresses.end(); bind_addr_iter++)
			{
				if((*bind_addr_iter).fd == fd  && (*bind_addr_iter).pid == pid)
				{
					bind_addr_iter = this->local_addresses.erase(bind_addr_iter);
					break;
				}
			}
		}
	}

	bool listeners_success = false;
	// std::list<ListeningSocket *>::iterator listener_iter;
	// if(!unbind_success && !bind_success)
	// {
	// 	if(!this->listeners.empty())
	// 	{
	// 		for(listener_iter=this->listeners.begin(); listener_iter!= this->listeners.end(); listener_iter++)
	// 		{
	// 			if((*listener_iter)->fd == fd  && (*listener_iter)->pid == pid)
	// 			{
	// 				delete (*listener_iter);
	// 				listener_iter = this->listeners.erase(listener_iter);
	// 				listeners_success = true;
	// 				break;
	// 			}
	// 		}
	// 	}
	// }

	// We should consider more cases when state is before ESTAB. I will solve this problem by making entire socket lists
	if(unbind_success || bind_success || listeners_success)
	{
		this->removeFileDescriptor(pid, fd);
		this->returnSystemCall(syscallUUID, 0);
	}
		
	else
	{
		// 2. If socket state is ESTAB, we should start active close (client side close)
		// Change socket state to FIN_WAIT_1, send FIN (FINACK) packet and , and block the systemcall
		// find socket in established list first
		std::list<Socket*>::iterator estab_iter;
		Socket *established_socket;
		bool find_established = false;
		if(!this->established_socks.empty())
		{
			for(estab_iter=this->established_socks.begin(); estab_iter!=this->established_socks.end(); estab_iter++)
			{
				if((*estab_iter)->fd == fd && (*estab_iter)->pid == pid)
				{
					find_established = true;
					established_socket = (*estab_iter);
				}
			}
		}
		
		if(!find_established)
		{
			this->removeFileDescriptor(pid, fd);
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		else // found established socket
		{
			// 2. If socket state is ESTAB, change state to FIN_WAIT_1 and send FIN (FINACK) packet, and deallocate fd, and returnsyscall 0
			if(established_socket->state == ESTAB)
			{
				std::cout<<"Client closing\n";

				established_socket->state = FIN_WAIT_1;

				this->removeFileDescriptor(pid, fd);
				this->returnSystemCall(syscallUUID, 0);

				if(established_socket->sender_buffer->allocated_buffer_size != 0)
				{
					std::cout<<"syscall_close called but internal sender buffer's allocated size is not 0\n";
					// for(auto temp_iter = established_socket->sender_buffer->payloads.begin(); temp_iter!=established_socket->sender_buffer->payloads.end(); temp_iter++)
					// {
					// 	printf("internal sender buffer's element's start num is %d, end num is %d\n",temp_iter->second.start_num, temp_iter->second.end_num);
					// }
					return;
				}

				if(!established_socket->sender_buffer->payloads.empty())
				{
					std::cout<<"syscall_close called, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
					return;
				}

				// std::cout<<"Client closing\n";
				// change socket state to ESTAB

				// send FIN(FINACK) packet
				int ip_header_size = 20;
				int tcp_header_size = 20;
				int payload_length = 0;
				Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
				//Packet *ack_packet = this->clonePacket(packet);
				PacketManager *finack_packet_manager = new PacketManager(finack_packet);
				finack_packet_manager->setSrcIpAddr(&(established_socket->local_ip_address));
				finack_packet_manager->setSrcPort(&(established_socket->local_port_num));
				finack_packet_manager->setDestIpAddr(&(established_socket->remote_ip_address));
				finack_packet_manager->setDestPort(&(established_socket->remote_port_num));
				unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
				finack_packet_manager->setSeqnum(&seq_num); // we should store appropriate seq num in socket
				//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
				unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
				finack_packet_manager->setAcknum(&ack_num); //we should store appropriate ack num in socket
				uint16_t window_size = htons(51200);
				finack_packet_manager->setWindowSize(&window_size);		
				finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
				finack_packet_manager->setChecksum();
				
				// Set FINACK packet timer
				Packet *clone_sent_packet = this->clonePacket(finack_packet);
				set_system_packet_timer(established_socket, clone_sent_packet, CLOSE_FINACK);
				
				this->sendPacket("IPv4", finack_packet);
				delete finack_packet_manager;

				// blocking systemcall
				// established_socket->syscall_id = syscallUUID;
				// return;
				// deallocate fd and returny syscall 0
			}

			else if(established_socket-> state == CLOSE_WAIT)
			{
				std::cout<<"Server closing\n";
				// 3. When systemcall close is called for server side
				// if socket state is CLOSE_WAIT change state to LAST_ACK, and BLOCK SENDING DATA!!!!(for pj3), send FIN(FINACK) packet to client and deallocate fd, and returnsyscall 0
				
				// change socket state to LAST_ACK
				established_socket->state = LAST_ACK;

				// send FIN(FINACK) packet
				int ip_header_size = 20;
				int tcp_header_size = 20;
				int payload_length = 0;
				Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
				//Packet *ack_packet = this->clonePacket(packet);
				PacketManager *finack_packet_manager = new PacketManager(finack_packet);
				finack_packet_manager->setSrcIpAddr(&(established_socket->local_ip_address));
				finack_packet_manager->setSrcPort(&(established_socket->local_port_num));
				finack_packet_manager->setDestIpAddr(&(established_socket->remote_ip_address));
				finack_packet_manager->setDestPort(&(established_socket->remote_port_num));
				unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
				finack_packet_manager->setSeqnum(&seq_num); // we should store appropriate seq num in socket
				//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
				unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
				finack_packet_manager->setAcknum(&ack_num); //we should store appropriate ack num in socket
				uint16_t window_size = htons(51200);
				finack_packet_manager->setWindowSize(&window_size);		
				finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
				finack_packet_manager->setChecksum();
				
				// Set FINACK packet timer
				Packet *clone_sent_packet = this->clonePacket(finack_packet);
				set_system_packet_timer(established_socket, clone_sent_packet, CLOSE_FINACK);
				
				this->sendPacket("IPv4", finack_packet);
				delete finack_packet_manager;

				// block systemcall
				// established_socket->syscall_id = syscallUUID;
				// return;
				// deallocate fd and returny syscall 0
				this->removeFileDescriptor(pid, fd);
				this->returnSystemCall(syscallUUID, 0);
			}
			else
			{
				std::cout<<"Somethings are goring wrong!! Closing socket is in established list but state is not ESTAB, not CLOSE_WAIT\n";
			}
			
		}
	}	
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
	//it should be ipv4 address, sockaddr_in structure
	//check whether it is ipv4 address or not
	if(addr->sa_family != AF_INET) // we don't consider for ipv6 just consither sa_family is AF_INET
	{
		std::cout<<"failed because sa family is not af_inet! \n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
	// std::cout<<"bind syscall is called with request : \n";
	// std::cout<<"request ip address is : "<<inet_ntoa(addr_in->sin_addr)<<"\n";
	// std::cout<<"request port num is : "<<ntohs(addr_in->sin_port)<<"\n";
	unsigned long local_ip_address = addr_in->sin_addr.s_addr;
	uint16_t local_port_num = addr_in->sin_port;
	
	//address is already allocated. bind should fail
	if(this->check_already_binded(sockfd, pid, local_ip_address, local_port_num))
	{
		// std::cout<<"failed because socket or address is binded! \n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	std::list<Socket*>::iterator unbind_iter;
	Socket *requested_socket;
	bool found_unbinded_request_socket = false;
	for(unbind_iter = this->unbinded_sockets.begin(); unbind_iter != this->unbinded_sockets.end(); unbind_iter++)
	{
		if((*unbind_iter)->fd == sockfd && (*unbind_iter)->pid == pid)
		{
			requested_socket = *unbind_iter;
			unbind_iter = this->unbinded_sockets.erase(unbind_iter); // bind 
			found_unbinded_request_socket = true;
			break;
		}
	}

	//Socket corresponding to sockfd is not created yet
	if(!found_unbinded_request_socket)
	{
		std::cout<<"failed because there's no socket in unbinded list \n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
		
	requested_socket->local_ip_address = local_ip_address;
	requested_socket->local_port_num = local_port_num;
	this->binded_sockets.push_back(requested_socket); //add socket information into binded list
	struct address_info local_addr_info;
	local_addr_info.fd = sockfd;
	local_addr_info.pid = requested_socket->pid;
	local_addr_info.local_ip_address = local_ip_address;
	local_addr_info.local_port_num = local_port_num;
	this->local_addresses.push_back(local_addr_info);
	this->returnSystemCall(syscallUUID, 0);
}

bool TCPAssignment::check_already_binded(int reqeust_fd, int request_pid, unsigned long request_ip_addr, uint16_t request_port_num)
{
	//std::list<Socket*>::iterator bind_iter;
	std::list<struct address_info>::iterator bind_addr_iter;
	if(!this->local_addresses.empty())
	{
		for(bind_addr_iter=this->local_addresses.begin(); bind_addr_iter != this->local_addresses.end() ;bind_addr_iter++)
		{
			//1. Check socket(fd) is already binded
			if((*bind_addr_iter).fd == reqeust_fd)
			{
				if((*bind_addr_iter).pid == request_pid)
				{
					//std::cout<<"failed because fd already binded \n";
					return true;
				}
			}

			//2. Check address is already binded
			//first check port number is identical
			uint16_t existing_port_num = (*bind_addr_iter).local_port_num;			
			if(existing_port_num == request_port_num)
			{
				//Second check ip address is overlapping
				unsigned long existing_ip_addr = (*bind_addr_iter).local_ip_address;
				if(existing_ip_addr==request_ip_addr || existing_ip_addr == htonl(INADDR_ANY) || request_ip_addr == htonl(INADDR_ANY))
				{
					if(existing_ip_addr==request_ip_addr){
						std::cout<<"failed because ip addr already binded \n";
					}
					else if(existing_ip_addr == htonl(INADDR_ANY)){
						//std::cout<<"failed because existing ip addr is 0 for the port \n";
					}
					else if(request_ip_addr == htonl(INADDR_ANY)){
						std::cout<<"failed because request ip addr is 0 for the port \n";
					}
					return true;
				}
			}
		}
	}
	return false;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	std::list<Socket*>::iterator bind_iter;
	for(bind_iter=this->binded_sockets.begin(); bind_iter != this->binded_sockets.end() ;bind_iter++)
	{
		if((*bind_iter)->fd == sockfd && (*bind_iter)->pid == pid)
		{			
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = (*bind_iter)->local_port_num;
			addr_in->sin_addr.s_addr = (*bind_iter)->local_ip_address;
			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*addrlen = (socklen_t)sizeof(*addr);

			//std::cout<<"found in binded socket list\n";
			this->returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	std::list<Socket *>::iterator client_iter;
	for(client_iter=this->established_socks.begin(); client_iter != this->established_socks.end() ;client_iter++)
	{
		if((*client_iter)->fd == sockfd && (*client_iter)->pid == pid)
		{
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = (*client_iter)->local_port_num;
			addr_in->sin_addr.s_addr = (*client_iter)->local_ip_address;
			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*addrlen = (socklen_t)sizeof(*addr);

			//std::cout<<"found in established client socket list\n";
			this->returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	//bool listener_find_success = false;
	//ListeningSocket *listening_socket;
	std::list<ListeningSocket *>::iterator listener_iter;
	for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
	{
		if((*listener_iter)->fd == sockfd && (*listener_iter)->pid == pid)
		{
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = (*listener_iter)->local_port_num;
			addr_in->sin_addr.s_addr = (*listener_iter)->local_ip_address;
			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*addrlen = (socklen_t)sizeof(*addr);

			//std::cout<<"found in listener socket list\n";
			this->returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	this->returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
	// 1. Pop cretaed but unbind socket in unbinded_sockets list
	std::list<Socket*>::iterator unbind_iter;
	Socket *socket_to_connect;
	bool unbind_find_success = false;
	for(unbind_iter=this->unbinded_sockets.begin(); unbind_iter != this->unbinded_sockets.end() ;unbind_iter++)
	{
		if((*unbind_iter)->fd == sockfd && (*unbind_iter)->pid==pid)
		{
			socket_to_connect = *unbind_iter;
			unbind_iter = this->unbinded_sockets.erase(unbind_iter);
			unbind_find_success = true;
			break;
		}
	}

	bool bind_find_success = false;
	if(!unbind_find_success)
	{
		std::list<Socket*>::iterator bind_iter;
		for(bind_iter=this->binded_sockets.begin(); bind_iter != this->binded_sockets.end() ;bind_iter++)
		{
			if((*bind_iter)->fd == sockfd && (*bind_iter)->pid==pid)
			{
				socket_to_connect = *bind_iter;
				bind_iter = this->binded_sockets.erase(bind_iter);
				bind_find_success = true;
				break;
			}
		}
	}

	// When there is no appropriate socket in unbinded_sockets list, connect fails
	if(!unbind_find_success && !bind_find_success)
	{
		std::cout<<"syscall_connect returned -1!!\n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// 2. Record destination remote address in socket
	struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
	unsigned long remote_ip_address = addr_in->sin_addr.s_addr;
	uint16_t remote_port_num = addr_in->sin_port;
	socket_to_connect->remote_ip_address = remote_ip_address;
	socket_to_connect->remote_port_num = remote_port_num;

	// 3. Conduct implicit binding (only when it is found for unbinded sockets list)
	unsigned long local_ip_address;
	uint16_t local_port_num;
	if(unbind_find_success)
	{
		in_addr_t remote_ip_address_h = ntohl(remote_ip_address);
		in_addr_t local_ip_address_pre;
		uint16_t local_port_num_h;
		int routing_table_index = this->getHost()->getRoutingTable((uint8_t *)&remote_ip_address_h);
		this->getHost()->getIPAddr((uint8_t *)&local_ip_address_pre, routing_table_index); // here is problem
		local_ip_address = local_ip_address_pre;
		while(true)
		{
			local_port_num_h = rand()%65535;
			if(!check_already_binded(sockfd, pid, local_ip_address, htons(local_port_num_h)))
				break;
		}
		local_port_num = htons(local_port_num_h);
		socket_to_connect->local_ip_address = local_ip_address;
		socket_to_connect->local_port_num = local_port_num;

		struct address_info local_addr_info;
		local_addr_info.fd = sockfd;
		local_addr_info.pid = socket_to_connect->pid;
		local_addr_info.local_ip_address = local_ip_address;
		local_addr_info.local_port_num = local_port_num;
		this->local_addresses.push_back(local_addr_info);
	}
	else //bind_find_success
	{
		local_ip_address = socket_to_connect->local_ip_address;
		local_port_num = socket_to_connect->local_port_num;
	}
	

	// 4. Change socket state to SYNSENT, save sequence number and put in con_synack_waiters list with syscall UUID
	//unsigned long seq_num = htonl(0);
	socket_to_connect->state = SYNSENT;
	//socket_to_connect->seq_num = seq_num;
	socket_to_connect->syscall_id = syscallUUID;
	this->con_synack_waiters.push_back(socket_to_connect); //list ?轅붽틓??????dictionary???轅붽틓??筌롪퉮彛????????몃즼??? fd??????轅붽틓?????

	// 5. Send synpacket to server
	int ip_header_size = 20;
	int tcp_header_size = 20;
	int payload_length = 0;
	Packet *syn_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
	PacketManager *syn_packet_manager = new PacketManager(syn_packet);
	syn_packet_manager->setSrcIpAddr(&local_ip_address);
	syn_packet_manager->setDestIpAddr(&remote_ip_address);
	syn_packet_manager->setSrcPort(&local_port_num);
	syn_packet_manager->setDestPort(&remote_port_num);

	// maybe sequence number and ack number might be sub problem
	
	unsigned long seq_num = 0; // set sequence number in here! should it be random?
	socket_to_connect->seq_num = seq_num; //store sequence number value in socket
	syn_packet_manager->setSeqnum(&seq_num);

	syn_packet_manager->setFlag(1, 0, 0);
	//uint8_t paylaod_buffer = 4;
	//syn_packet_manager->setPayload(&paylaod_buffer, 1);
	uint16_t window_size = htons(51200);
	syn_packet_manager->setWindowSize(&window_size);
	syn_packet_manager->setChecksum();

	Packet *clone_sent_packet = this->clonePacket(syn_packet);
	set_system_packet_timer(socket_to_connect, clone_sent_packet, ESTAB_SYN);

	this->sendPacket("IPv4", syn_packet);
	delete syn_packet_manager;

	return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	//should it search for only client_established_socks or also server_established_socks?
	std::list<Socket *>::iterator client_iter;
	for(client_iter=this->con_synack_waiters.begin(); client_iter != this->con_synack_waiters.end() ;client_iter++)
	{
		if((*client_iter)->fd == sockfd && (*client_iter)->pid == pid)
		{			
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = (*client_iter)->remote_port_num;
			addr_in->sin_addr.s_addr = (*client_iter)->remote_ip_address;
			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*addrlen = (socklen_t)sizeof(*addr);

			this->returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	//std::list<Socket *>::iterator client_iter;
	for(client_iter=this->established_socks.begin(); client_iter != this->established_socks.end() ;client_iter++)
	{
		if((*client_iter)->fd == sockfd && (*client_iter)->pid == pid)
		{			
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = (*client_iter)->remote_port_num;
			addr_in->sin_addr.s_addr = (*client_iter)->remote_ip_address;
			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*addrlen = (socklen_t)sizeof(*addr);

			this->returnSystemCall(syscallUUID, 0);
			return;
		}
	}

	std::list<ListeningSocket *>::iterator listener_iter;
	std::list<Socket *>::iterator server_iter;
	for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
	{
		for(server_iter=(*listener_iter)->pending_connections.begin(); server_iter !=(*listener_iter)->pending_connections.end(); server_iter++)
		{
			if((*server_iter)->fd == sockfd && (*server_iter)->pid == pid)
			{
				struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
				addr_in->sin_family = AF_INET;
				addr_in->sin_port = (*server_iter)->remote_port_num;
				addr_in->sin_addr.s_addr = (*server_iter)->remote_ip_address;
				for(int i=0;i<8;i++)
				{
					addr_in->sin_zero[i] = 0;
				}
				*addrlen = (socklen_t)sizeof(*addr);

				this->returnSystemCall(syscallUUID, 0);
				return;			
			}
		}
		for(server_iter=(*listener_iter)->accepted_connections.begin(); server_iter !=(*listener_iter)->accepted_connections.end(); server_iter++)
		{
			if((*server_iter)->fd == sockfd && (*server_iter)->pid == pid)
			{
				struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
				addr_in->sin_family = AF_INET;
				addr_in->sin_port = (*server_iter)->remote_port_num;
				addr_in->sin_addr.s_addr = (*server_iter)->remote_ip_address;
				for(int i=0;i<8;i++)
				{
					addr_in->sin_zero[i] = 0;
				}
				*addrlen = (socklen_t)sizeof(*addr);

				this->returnSystemCall(syscallUUID, 0);
				return;	
			}
		}
	}

	this->returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	// 1. Pop socket in the binded list
	bool bind_find_success = false;
	Socket *socket_to_listen;
	std::list<Socket*>::iterator bind_iter;
	for(bind_iter=this->binded_sockets.begin(); bind_iter != this->binded_sockets.end() ;bind_iter++)
	{
		if((*bind_iter)->fd == sockfd && (*bind_iter)->pid == pid)
		{
			socket_to_listen = *bind_iter;
			bind_iter = this->binded_sockets.erase(bind_iter);
			bind_find_success = true;
			break;
		}
	}

	if(!bind_find_success)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	// 2. Create corresponding listening socket and free original socket to listen
	ListeningSocket *listening_socket = new ListeningSocket(socket_to_listen->pid, socket_to_listen->fd,
	socket_to_listen->local_ip_address, socket_to_listen->local_port_num, backlog);
	delete socket_to_listen;

	// 3. Put created listening_socket into listeners list
	this->listeners.push_back(listening_socket);

	this->returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	// 1. Search listeing socket in the listeners list
	bool listener_find_success = false;
	ListeningSocket *listening_socket;
	std::list<ListeningSocket *>::iterator listener_iter;
	for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
	{
		if((*listener_iter)->fd == sockfd && (*listener_iter)->pid == pid)
		{
			listening_socket = *listener_iter;
			//listener_iter = this->listeners.erase(listener_iter);
			listener_find_success = true;
			break;
		}
	}

	if(!listener_find_success)
	{
		//std::cout<<"accept failed because there is no appropriate listening socket for sockfd\n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// 2. Check accepted connections of the listening socket is empty or not
	if(!listening_socket->accepted_connections.empty())
	{
		// there is accepted connections, we can return syscall right now, without blocking
		// Get accepted socket in accepted connections list and take it out from list
		Socket *connection_socket = listening_socket->accepted_connections.front();
		listening_socket->accepted_connections.pop_front();
		
		// Change socket's state to establisehd and put it into established connections list in listening socket.
		//connection_socket->state = ESTAB;
		int new_allocated_fd = this->createFileDescriptor(pid);
		connection_socket->fd = new_allocated_fd;
		connection_socket->pid = pid;
		//listening_socket->established_connections.push_back(connection_socket);
		//this->established_socks.push_back(connection_socket);

		// Record remote address for parameter input
		struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = connection_socket->remote_port_num;
		addr_in->sin_addr.s_addr = connection_socket->remote_ip_address;

		for(int i=0;i<8;i++)
		{
			addr_in->sin_zero[i] = 0;
		}
		*addrlen = (socklen_t)sizeof(*addr);

		// It doesn't have to be blocked, so return Systemclal immediately with fd.
		this->returnSystemCall(syscallUUID, connection_socket->fd);
		return;
	}
	//accepted_connections list is empty
	else // there are no any accepted connections, we should store information and be blocked (wait for accepting)
	{
		struct acceptRequest accept_request;
		accept_request.syscall_id = syscallUUID;
		accept_request.addr = addr;
		accept_request.addrlen = addrlen;
		accept_request.pid = pid;

		listening_socket->accept_requests.push_back(accept_request);
		//listening_socket->accept_request = accept_request;
		
		return;
	}
	
	return;

	// 3. put sockt into

	// int fd;
	// unsigned long local_ip_address;
	// uint16_t local_port_num;
	// unsigned long remote_ip_address;
	// uint16_t remote_port_num;
	// socket_state state;
	// UUID syscall_id;

	// unsigned long seq_num;
	// unsigned long ack_num;
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count)
{
	// find socket in established_socks list
	std::list<Socket *>::iterator socket_iter;
	bool found_socket = false;
	Socket *writing_socket = NULL;
	for(socket_iter=this->established_socks.begin(); socket_iter != this->established_socks.end() ;socket_iter++)
	{
		if((*socket_iter)->fd == sockfd && (*socket_iter)->pid == pid)
		{
			writing_socket = *socket_iter;
			found_socket = true;
			break;			
		}
	}

	if(!found_socket)
	{
		std::cout<<"Tried to write systemcall, but cannot find socket in established socks.\n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// if(writing_socket->state == FIN_WAIT_1 || writing_socket->state == FIN_WAIT_2 || writing_socket->state == TIMED_WAIT ||
	// 	writing_socket->state == CLOSING|| writing_socket->state == LAST_ACK)
	// 	{
	// 		std::cout<<"Tried to write systemcall, but socket state is in closing so returend -1.\n";
	// 		this->returnSystemCall(syscallUUID, -1);
	// 		return;
	// 	}

	if(writing_socket->state > ESTAB && writing_socket->state != CLOSE_WAIT)
		{
			std::cout<<"Tried to write systemcall, but socket state is in closing so returend -1.\n";
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

	// block the systemcall
	// if(writing_socket->sender_buffer->remained_buffer_size == 0)
	// {
		
	// 	struct blocked_syscall_info blocked_write;
	// 	blocked_write.category = WRITE_SYSCALL;
	// 	blocked_write.syscall_id = syscallUUID;
	// 	blocked_write.buf = buf;
	// 	blocked_write.count = count;
	// 	writing_socket->blocked_syscall.push_back(blocked_write);
	// 	return;
	// }
	// else
	// {
	// 	size_t copied_data_size = save_internal_sender_buffer(buf, writing_socket->sender_buffer, count);
	// 	this->send_data(writing_socket);
	// 	this->returnSystemCall(syscallUUID, copied_data_size);
	// 	return;
	// }
	
	if(writing_socket->this_time_send)
	{
		writing_socket->this_time_send = !writing_socket->this_time_send;

		if(writing_socket->sender_buffer->remained_buffer_size == 0)
		{
			
			struct blocked_syscall_info blocked_write;
			blocked_write.category = WRITE_SYSCALL;
			blocked_write.syscall_id = syscallUUID;
			blocked_write.buf = buf;
			blocked_write.count = count;
			writing_socket->blocked_syscall.push_back(blocked_write);
			return;
		}
		else
		{
			size_t copied_data_size = save_internal_sender_buffer(buf, writing_socket->sender_buffer, count);
			this->send_data(writing_socket);
			this->returnSystemCall(syscallUUID, copied_data_size);
			return;
		}
	}

	if(!writing_socket->this_time_send)
	{
		writing_socket->this_time_send = !writing_socket->this_time_send;

		struct blocked_syscall_info blocked_write;
		blocked_write.category = WRITE_SYSCALL;
		blocked_write.syscall_id = syscallUUID;
		blocked_write.buf = buf;
		blocked_write.count = count;
		writing_socket->blocked_syscall.push_back(blocked_write);
		return;
	}

	return;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count)
{
	// find socket in established_socks list
	std::list<Socket *>::iterator socket_iter;
	bool found_socket = false;
	Socket *reading_socket = NULL;
	for(socket_iter=this->established_socks.begin(); socket_iter != this->established_socks.end() ;socket_iter++)
	{
		if((*socket_iter)->fd == sockfd && (*socket_iter)->pid == pid)
		{
			reading_socket = *socket_iter;
			found_socket = true;
			break;			
		}
	}

	if(!found_socket)
	{
		std::cout<<"Tried to read systemcall, but cannot find socket in established socks.\n";
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// if(reading_socket->state == TIMED_WAIT)
	// {
	// 	std::cout<<"Tried to read systemcall, but socket state is in closing so returend -1.\n";
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }

	// if(reading_socket->state == TIMED_WAIT || reading_socket->state == CLOSING || reading_socket->state == CLOSE_WAIT || reading_socket->state == LAST_ACK)
	// {
	// 	std::cout<<"Tried to read systemcall, but socket state is in closing so returend 0.\n";
	// 	this->returnSystemCall(syscallUUID, 0);
	// 	return;
	// }

	// if(reading_socket->state > ESTAB && reading_socket->state != CLOSE_WAIT)
	// {
	// 	std::cout<<"Tried to read systemcall, but socket state is in closing so returend -1.\n";
	// 	this->returnSystemCall(syscallUUID, -1);
	// 	return;
	// }

	if(count==0)
	{
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	if(reading_socket->receiver_buffer->allocated_buffer_size == 0 )
	{		
		struct blocked_syscall_info blocked_read;
		blocked_read.category = READ_SYSCALL;
		blocked_read.syscall_id = syscallUUID;
		blocked_read.buf = buf;
		blocked_read.count = count;
		reading_socket->blocked_syscall.push_back(blocked_read);
		return;	
	}

	// std::cout<<"case1: reading direectly from read syscall\n";
	size_t readed_data_size = read_internal_receiver_buffer(reading_socket, (uint8_t *)buf, reading_socket->receiver_buffer, count);

	// if(readed_data_size == 0)
	// {
	// 	// send ack packet for received packet
	// 	unsigned long new_ack_num = (unsigned long)reading_socket->receiver_buffer->consecutive_cursor;
	// 	reading_socket->ack_num = new_ack_num;
	// 	unsigned long new_seq_num = (unsigned long)reading_socket->seq_num;
	// 	reading_socket->seq_num = new_seq_num;
	// 	unsigned long src_ip = reading_socket->local_ip_address;
	// 	unsigned long dest_ip = reading_socket->remote_ip_address;
	// 	uint16_t src_port = reading_socket->local_port_num;
	// 	uint16_t dest_port = reading_socket->remote_port_num;
	// 	this->send_packet(reading_socket, &src_ip , &dest_ip, &src_port, &dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
	// }
	
	// if(readed_data_size == 0 )
	// {
	// 	struct blocked_syscall_info blocked_write;
	// 	blocked_write.category = READ_SYSCALL;
	// 	blocked_write.syscall_id = syscallUUID;
	// 	blocked_write.buf = buf;
	// 	blocked_write.count = count;
	// 	reading_socket->blocked_syscall.push_back(blocked_write);
	// 	return;	
	// }

	if(readed_data_size == 0)
	{
		struct blocked_syscall_info blocked_read;
		blocked_read.category = READ_SYSCALL;
		blocked_read.syscall_id = syscallUUID;
		blocked_read.buf = buf;
		blocked_read.count = count;
		reading_socket->blocked_syscall.push_back(blocked_read);
		return;	
	}

	this->returnSystemCall(syscallUUID, readed_data_size);

	// return;

	// this->returnSystemCall(syscallUUID, -1);
	return;
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

bool isSynack(PacketManager *received_packet_manager)
{
	// 1. Check both syn bit and ack bit is true
	uint16_t *flag = new uint16_t; 
	received_packet_manager->getFlag(flag);
	*flag = ntohs(*flag);
	*flag = *flag & (0x003f);

	// check syn bit
	uint16_t syn = !!(*flag & (1<<1));
	//std::cout<<"syn value is : "<< syn << '\n';

	// check ack bit
	uint16_t ack = !!(*flag & (1<<4));
	//std::cout<<"ack value is : "<< ack << '\n';

	// check fin bit
	uint16_t fin = !!(*flag & (1));
	//std::cout<<"fin value is : "<< fin << '\n';

	delete flag;
	if(syn!=0 && ack!=0 && fin==0) //check here please if error occurs for previous test
		return true;
	return false;
}

bool isSyn(PacketManager *received_packet_manager)
{
	// 1. Check syn bit is true and ack bit is false
	uint16_t *flag = new uint16_t; 
	received_packet_manager->getFlag(flag);
	*flag = ntohs(*flag);
	*flag = *flag & (0x003f);

	// check syn bit
	uint16_t syn = !!(*flag & (1<<1));
	//std::cout<<"syn value is : "<< syn << '\n';

	// check ack bit
	uint16_t ack = !!(*flag & (1<<4));
	//std::cout<<"ack value is : "<< ack << '\n';

	// check fin bit
	uint16_t fin = !!(*flag & (1));
	//std::cout<<"fin value is : "<< fin << '\n';

	delete flag;
	if(syn!=0 && ack==0 & fin==0)
		return true;
	return false;
}

bool isAck(PacketManager *received_packet_manager)
{
	// 1. Check syn bit is false and ack bit is true
	uint16_t *flag = new uint16_t; 
	received_packet_manager->getFlag(flag);
	*flag = ntohs(*flag);
	*flag = *flag & (0x003f);

	// check syn bit
	uint16_t syn = !!(*flag & (1<<1));
	//std::cout<<"syn value is : "<< syn << '\n';

	// check ack bit
	uint16_t ack = !!(*flag & (1<<4));
	//std::cout<<"ack value is : "<< ack << '\n';

	// check fin bit
	uint16_t fin = !!(*flag & (1));
	//std::cout<<"fin value is : "<< fin << '\n';

	delete flag;
	if(syn==0 && ack!=0 & fin==0)
		return true;
	return false;
}

bool isFinack(PacketManager *received_packet_manager) // FIN(FINACK)
{
	// 1. Check syn bit is false and ack bit is true
	uint16_t *flag = new uint16_t; 
	received_packet_manager->getFlag(flag);
	*flag = ntohs(*flag);
	*flag = *flag & (0x003f);

	// check syn bit
	uint16_t syn = !!(*flag & (1<<1));
	//std::cout<<"syn value is : "<< syn << '\n';

	// check ack bit
	uint16_t ack = !!(*flag & (1<<4));
	//std::cout<<"ack value is : "<< ack << '\n';

	// check fin bit
	uint16_t fin = !!(*flag & (1));
	//std::cout<<"fin value is : "<< fin << '\n';

	delete flag;
	if(syn==0 && ack!=0 && fin!=0)
		return true;
	return false;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	PacketManager *arrived_packet_manager = new PacketManager(packet);
	unsigned long *src_ip = new unsigned long;
	unsigned long *dest_ip = new unsigned long;
	uint16_t *src_port = new uint16_t;
	uint16_t *dest_port = new uint16_t; // comsider unsgined long->uint32_t, int (for port num)->uint16_t later
	unsigned long *seq_num = new unsigned long;
	unsigned long *ack_num = new unsigned long;
	arrived_packet_manager->getSrcIpAddr(src_ip);
	arrived_packet_manager->getDestIpAddr(dest_ip);
	arrived_packet_manager->getSrcPort(src_port);
	arrived_packet_manager->getDestPort(dest_port);
	arrived_packet_manager->getSeqnum(seq_num);
	arrived_packet_manager->getAcknum(ack_num);

	//we need checksum checking process!!! 
	

	if(isSyn(arrived_packet_manager))
	{
		// find corresponding listening socket in listeners
		bool listener_find_success = false;
		ListeningSocket *listening_socket = NULL;
		std::list<ListeningSocket *>::iterator listener_iter;
		for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
		{
			if( ((*listener_iter)->local_ip_address == *dest_ip || (*listener_iter)->local_ip_address == INADDR_ANY) &&
			((*listener_iter)->local_port_num == *dest_port) )
			{
				listening_socket = *listener_iter;
				//listener_iter = this->listeners.erase(listener_iter);
				listener_find_success = true;
				break;
			}
		}

		// ignore if there are not any corresponding listening socket
		if(!listener_find_success)
		{
			bool synsent_find_success = false;
			Socket *synsent_socket = NULL;
			std::list<Socket *>::iterator synack_waiters_iter;
			for(synack_waiters_iter = this->con_synack_waiters.begin(); 
			synack_waiters_iter != this->con_synack_waiters.end();
			synack_waiters_iter++)
			{
				if( ((*synack_waiters_iter)->local_ip_address == *dest_ip || (*synack_waiters_iter)->local_ip_address == INADDR_ANY) &&
				((*synack_waiters_iter)->local_port_num == *dest_port) &&
				((*synack_waiters_iter)->remote_ip_address == *src_ip || (*synack_waiters_iter)->remote_ip_address == INADDR_ANY) &&
				((*synack_waiters_iter)->remote_port_num == *src_port))
				{
					synsent_find_success = true;
					synsent_socket = *synack_waiters_iter;
					// case synack is arrived but acknum & seq_num +1 doesn't match should ignore until it comes again
					break;
				}
			}

			if(synsent_find_success)
			{
				if(!remove_system_packet_timer(synsent_socket, ESTAB_SYN))
				{
					std::cout<<"received syn at synsent state, but syn timer was off. Something's wrong\n";
					return;
				}

				// we should send SYNACK packet. this case is simultaneous open
				int ip_header_size = 20;
				int tcp_header_size = 20;
				int payload_length = 0;

				unsigned long new_seq_num = synsent_socket->seq_num;
				unsigned long new_ack_num = ntohl(*seq_num)+1;
				//synsent_socket->seq_num = new_seq_num;
				synsent_socket->ack_num = new_ack_num;

				Packet *synack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
				PacketManager *synack_packet_manager = new PacketManager(synack_packet);
				synack_packet_manager->setSrcIpAddr(dest_ip);
				synack_packet_manager->setSrcPort(dest_port);
				synack_packet_manager->setDestIpAddr(src_ip);
				synack_packet_manager->setDestPort(src_port);
				new_seq_num = htonl(new_seq_num);
				synack_packet_manager->setSeqnum(&new_seq_num);
				new_ack_num = htonl(new_ack_num);
				synack_packet_manager->setAcknum(&new_ack_num);
				uint16_t window_size = htons(51200);
				synack_packet_manager->setWindowSize(&window_size);		
				synack_packet_manager->setFlag(1, 1, 0);	
				synack_packet_manager->setChecksum();

				// set synack timer
				Packet *clone_sent_packet = this->clonePacket(synack_packet);
				set_system_packet_timer(synsent_socket, clone_sent_packet, ESTAB_SYNACK);

				this->sendPacket("IPv4", synack_packet);
				delete synack_packet_manager;

				
				// if(!remove_packet_timer(synsent_socket, ESTAB_SYN))
				// {
				// 	std::cout<<"received syn at synsent state, but syn timer was off\n";
				// 	if(!remove_packet_timer(synsent_socket, ESTAB_SYNACK))
				// 	{
				// 		std::cout<<"received syn at synsent state, but synack timer was off too. Something's wrong\n";
				// 	}
				// 	//return;
				// }

				// // we should send SYNACK packet. this case is simultaneous open
				// int ip_header_size = 20;
				// int tcp_header_size = 20;
				// int payload_length = 0;

				// unsigned long new_seq_num = synsent_socket->seq_num;
				// unsigned long new_ack_num = ntohl(*seq_num)+1;
				// //synsent_socket->seq_num = new_seq_num;
				// synsent_socket->ack_num = new_ack_num;

				// Packet *synack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
				// PacketManager *synack_packet_manager = new PacketManager(synack_packet);
				// synack_packet_manager->setSrcIpAddr(dest_ip);
				// synack_packet_manager->setSrcPort(dest_port);
				// synack_packet_manager->setDestIpAddr(src_ip);
				// synack_packet_manager->setDestPort(src_port);
				// new_seq_num = htonl(new_seq_num);
				// synack_packet_manager->setSeqnum(&new_seq_num);
				// new_ack_num = htonl(new_ack_num);
				// synack_packet_manager->setAcknum(&new_ack_num);
				// uint16_t window_size = htons(51200);
				// synack_packet_manager->setWindowSize(&window_size);		
				// synack_packet_manager->setFlag(1, 1, 0);	
				// synack_packet_manager->setChecksum();

				// // set synack timer
				// Packet *clone_sent_packet = this->clonePacket(synack_packet);
				// set_packet_timer(synsent_socket, clone_sent_packet, ESTAB_SYNACK);

				// this->sendPacket("IPv4", synack_packet);
				// delete synack_packet_manager;
			}
			else
			{
				std::cout<<"Syn packet receiving failed because there are no corresponding listening socket\n";
			}
			
			return;
		}

		if(listening_socket->pending_connections.size() == listening_socket->backlog)
		{
			// Limit situation. pending connectiosn number is equal to backlog. So no more
			// connection can be added
			//std::cout<<"Syn packet receiving failed because pending_connection size is equal with backlog\n";
			return;
		}
		else if(listening_socket->pending_connections.size() > listening_socket->backlog)
		{
			// Somethings wrong. pending connections number exceeds backlog. So no more
			// connection can be added
			//std::cout<<"Syn packet receiving failed because pending_connection size is bigger than backlog\n";
			return;
		}
		else
		{
			// pending connections number is smaller than backlog. Connection available
			// Create new fd allocated duplicated(from listening socket) socket and put it in pending connetions list in listening socket
			//int new_allocated_fd = this->createFileDescriptor(listening_socket->pid);
			//Socket *connection_socket = new Socket(new_allocated_fd);
			Socket *connection_socket = new Socket(0,0, MSS, 51200);
			// connection_socket->local_ip_address = listening_socket->local_ip_address;
			// connection_socket->local_port_num = listening_socket->local_port_num;
			connection_socket->local_ip_address = *dest_ip;
			connection_socket->local_port_num = *dest_port;
			connection_socket->remote_ip_address = *src_ip;
			connection_socket->remote_port_num = *src_port;
			connection_socket->state = SYNRCVD;

			unsigned long new_seq_num = 0;// we can set seq_num in here should it be random?
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			connection_socket->seq_num = new_seq_num;
			connection_socket->ack_num = new_ack_num;
			//connection_socket->syscall_id = listening_socket->syscallUUID;

			//this->acc_waiters.push_back(connection_socket);
			listening_socket->pending_connections.push_back(connection_socket);

			// After duplicating, server should send SYNACK
			// Should send SYNACK packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *synack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *synack_packet_manager = new PacketManager(synack_packet);
			synack_packet_manager->setSrcIpAddr(dest_ip);
			synack_packet_manager->setSrcPort(dest_port);
			synack_packet_manager->setDestIpAddr(src_ip);
			synack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			synack_packet_manager->setSeqnum(&new_seq_num);
			new_ack_num = htonl(new_ack_num);
			synack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			synack_packet_manager->setWindowSize(&window_size);		
			synack_packet_manager->setFlag(1, 1, 0);	
			synack_packet_manager->setChecksum();

			Packet *clone_sent_packet = this->clonePacket(synack_packet);
			set_system_packet_timer(connection_socket, clone_sent_packet, ESTAB_SYNACK);

			this->sendPacket("IPv4", synack_packet);
			delete synack_packet_manager;
			// this->returnSystemCall(corr_conn_socket->syscall_id, 0);
			// return;
		}
		return;
	}

	else if(isAck(arrived_packet_manager))
	{
		// find packet in established_socks list. Their state will be eqaul or later than ESTAB
		std::list<Socket*>::iterator estab_iter;
		Socket *established_socket;
		bool find_established = false;
		if(!this->established_socks.empty())
		{
			for(estab_iter=this->established_socks.begin(); estab_iter!=this->established_socks.end(); estab_iter++)
			{
				
				// struct in_addr dest_ip_temp;
				// dest_ip_temp.s_addr = *dest_ip;
				// struct in_addr src_ip_temp;
				// src_ip_temp.s_addr = *src_ip;
				// struct in_addr local_ip_temp;
				// local_ip_temp.s_addr = (*estab_iter)->local_ip_address;
				// struct in_addr remote_ip_temp;
				// remote_ip_temp.s_addr = (*estab_iter)->remote_ip_address;
				// std::cout<<"received_packet's dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
				// std::cout<<"received_packet's dest_port is : "<<ntohs(*dest_port)<<"\n";
				// std::cout<<"received_packet's src_ip is : "<<inet_ntoa(src_ip_temp)<<"\n";
				// std::cout<<"received_packet's src_port is : "<<ntohs(*src_port)<<"\n";
				// std::cout<<"established socket's local_ip is : "<<inet_ntoa(local_ip_temp)<<"\n";
				// std::cout<<"established socket's local_port is : "<<ntohs((*estab_iter)->local_port_num )<<"\n";
				// std::cout<<"established socket's remote_ip is : "<<inet_ntoa(remote_ip_temp)<<"\n";
				// std::cout<<"established socket's remote_port is : "<<ntohs((*estab_iter)->remote_port_num)<<"\n";
				

				if( ((ntohl((*estab_iter)->local_ip_address) == ntohl(*dest_ip) || (*estab_iter)->local_ip_address == INADDR_ANY)) &&
				((*estab_iter)->local_port_num == *dest_port) &&
				(( ntohl((*estab_iter)->remote_ip_address) == ntohl(*src_ip) || (*estab_iter)->remote_ip_address == INADDR_ANY)) &&
				((*estab_iter)->remote_port_num == *src_port) )
				{
					established_socket = *estab_iter;
					find_established = true;
					break;
				}
			}
		}

		// Their state is eqaul or later than ESTAB. It's finishing process
		if(find_established)
		{
			// struct in_addr local_ip_temp;
			// local_ip_temp.s_addr = established_socket->local_ip_address;
			// struct in_addr remote_ip_temp;
			// remote_ip_temp.s_addr = established_socket->remote_ip_address;
			// std::cout<<"Answer established socket's local_ip is : "<<inet_ntoa(local_ip_temp)<<"\n";
			// std::cout<<"Answer established socket's local_port is : "<<ntohs(established_socket->local_port_num )<<"\n";
			// std::cout<<"Answer established socket's remote_ip is : "<<inet_ntoa(remote_ip_temp)<<"\n";
			// std::cout<<"Answer established socket's remote_port is : "<<ntohs(established_socket->remote_port_num)<<"\n";

			uint16_t ip_length = 0;
			arrived_packet_manager->getIpLength(&ip_length);
			int payload_length = ntohs(ip_length) - 20 - 20;

			// When received ACK packet of active close. Client side
			if(established_socket->state == FIN_WAIT_1)
			{
				if(remove_system_packet_timer(established_socket, ESTAB_SYNACK))
				{
					// if there was synack_timer, remove it and skip under process since it's for closing
					return;
				}

				if (established_socket->sender_buffer->allocated_buffer_size != 0)
				{
					if(established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in FIN_WAIT_1 state, and sender buffer allocated size is not 0 but payloads is empty\n";
						return;
					}

					// Case when get ack of sent data packet
					// Remove data from internal sender buffer
					unsigned long ack_num_h = ntohl(*ack_num);
					uint16_t new_rwnd = 0;
					arrived_packet_manager->getWindowSize(&new_rwnd);
					new_rwnd = ntohs(new_rwnd);
					established_socket->target_rwnd = new_rwnd;
					data_ack_process(ack_num_h, established_socket, new_rwnd, payload_length);

					// Check wheter internal sender buffer is empty. If empty, send the ack of FINACK packet
					if(established_socket->sender_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->sender_buffer->payloads.empty())
						{
							std::cout<<"Received ack in FIN_WAIT_1 state, and sender buffer allocated size is 0 but payloads is not empty\n";
							return;
						}
						unsigned long new_ack_num = established_socket->ack_num;
						unsigned long new_seq_num = established_socket->seq_num; // why new_seq_num be 2 not 1 in refernce???
						send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 1, false, NULL ,0);
					}
					return;
				}

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in FIN_WAIT_1, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}

				if(!remove_system_packet_timer(established_socket, CLOSE_FINACK))
				{
					// std::cout<<"received ack packet in FIN_WAIT_1 socket, but there is no FINACK timer\n"; # 3
					return;
				}

				// Change state to FIN_WAIT_2
				if(ntohl(*ack_num) == established_socket->seq_num+1 && ntohl(*seq_num) == established_socket->ack_num) //seq num & ack num check
				{
					established_socket->state = FIN_WAIT_2;
					//std::cout<<"changed state to fin_wait_2!!\n";
				}
				return;
			}
			
			else if(established_socket->state == FIN_WAIT_2)
			{
				if (established_socket->sender_buffer->allocated_buffer_size != 0)
				{
					if(established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in FIN_WAIT_2 state, and sender buffer allocated size is not 0 but payloads is empty\n";
						return;
					}

					// Case when get ack of sent data packet
					// Remove data from internal sender buffer
					unsigned long ack_num_h = ntohl(*ack_num);
					uint16_t new_rwnd = 0;
					arrived_packet_manager->getWindowSize(&new_rwnd);
					new_rwnd = ntohs(new_rwnd);
					established_socket->target_rwnd = new_rwnd;
					data_ack_process(ack_num_h, established_socket, new_rwnd, payload_length);

				}

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in FIN_WAIT_2, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}

				return;
			}

			// When received ack packet of passive close. Server side
			// // send FIN(FINACK) packet
			// int ip_header_size = 20;
			// int tcp_header_size = 20;
			// int payload_length = 0;
			// Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			// //Packet *ack_packet = this->clonePacket(packet);
			// PacketManager *finack_packet_manager = new PacketManager(finack_packet);
			// finack_packet_manager->setSrcIpAddr(&(established_socket->local_ip_address));
			// finack_packet_manager->setSrcPort(&(established_socket->local_port_num));
			// finack_packet_manager->setDestIpAddr(&(established_socket->remote_ip_address));
			// finack_packet_manager->setDestPort(&(established_socket->remote_port_num));
			// unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
			// finack_packet_manager->setSeqnum(&seq_num); // we should store appropriate seq num in socket
			// //unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			// unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
			// finack_packet_manager->setAcknum(&ack_num); //we should store appropriate ack num in socket
			// uint16_t window_size = htons(51200);
			// finack_packet_manager->setWindowSize(&window_size);		
			// finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
			// finack_packet_manager->setChecksum();
			
			// // Set FINACK packet timer
			// Packet *clone_sent_packet = this->clonePacket(finack_packet);
			// set_system_packet_timer(established_socket, clone_sent_packet, CLOSE_FINACK);
			
			// this->sendPacket("IPv4", finack_packet);
			// delete finack_packet_manager;

			else if(established_socket->state == LAST_ACK)
			{
				if (established_socket->sender_buffer->allocated_buffer_size == 0)
				{
					if(!established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in LAST_ACK state, and sender buffer allocated size is 0 but payloads is not empty\n";
						return;
					}

					// Case when get ack of FINACK packet
					// it should remove FINACK timer
					if(!remove_system_packet_timer(established_socket, CLOSE_FINACK))
					{
						std::cout<<"received ack packet in LAST_ACK socket, but there's no finack timer\n";
						return;
					}

					// free the memory and erase from socket list
					if(ntohl(*ack_num) == established_socket->seq_num+1 && ntohl(*seq_num) == established_socket->ack_num) //seq num & ack num check
					{
						// std::cout<<"Connection end. Closing server side. eliminated socket from estalished_socks\n";
						this->established_socks.erase(estab_iter);
						delete established_socket;
					}
					return;
				}

				else
				{
					if(established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in LAST_ACK state, and sender buffer allocated size is not 0 but payloads is empty\n";
						return;
					}

					if(payload_length == 0)
					{
						// Case when get ack of sent data packet
						// Remove data from internal sender buffer
						unsigned long ack_num_h = ntohl(*ack_num);
						uint16_t new_rwnd = 0;
						arrived_packet_manager->getWindowSize(&new_rwnd);
						new_rwnd = ntohs(new_rwnd);
						established_socket->target_rwnd = new_rwnd;
						data_ack_process(ack_num_h, established_socket, new_rwnd, payload_length);

						// Check wheter internal sender buffer is empty. If empty, send the ack of FINACK packet
						if(established_socket->sender_buffer->allocated_buffer_size == 0)
						{
							if(!established_socket->sender_buffer->payloads.empty())
							{
								std::cout<<"Received ack in LAST_ACK state, and sender buffer allocated size is 0 but payloads is not empty\n";
								return;
							}
							unsigned long new_ack_num = ntohl(*seq_num)+1;
							unsigned long new_seq_num = ntohl(*ack_num)+1; // why new_seq_num be 2 not 1 in refernce???
							send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}				
					}

				}

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in LAST_ACK, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);

						if(established_socket->receiver_buffer->allocated_buffer_size == 0)
						{
							if(!established_socket->receiver_buffer->payloads.empty())
							{
								printf("In LAST_ACK, readed data and allocated size is 0 but receiver buffer's payloads is not empty\n");
								return;
							}
							// send FIN(FINACK) packet
							int ip_header_size = 20;
							int tcp_header_size = 20;
							Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + 0);
							//Packet *ack_packet = this->clonePacket(packet);
							PacketManager *finack_packet_manager = new PacketManager(finack_packet);
							finack_packet_manager->setSrcIpAddr(&(established_socket->local_ip_address));
							finack_packet_manager->setSrcPort(&(established_socket->local_port_num));
							finack_packet_manager->setDestIpAddr(&(established_socket->remote_ip_address));
							finack_packet_manager->setDestPort(&(established_socket->remote_port_num));
							unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
							finack_packet_manager->setSeqnum(&seq_num); // we should store appropriate seq num in socket
							//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
							unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
							finack_packet_manager->setAcknum(&ack_num); //we should store appropriate ack num in socket
							uint16_t window_size = htons(51200);
							finack_packet_manager->setWindowSize(&window_size);		
							finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
							finack_packet_manager->setChecksum();
							
							// Set FINACK packet timer
							Packet *clone_sent_packet = this->clonePacket(finack_packet);
							set_system_packet_timer(established_socket, clone_sent_packet, CLOSE_FINACK);
							
							this->sendPacket("IPv4", finack_packet);
							delete finack_packet_manager;
						}
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);

							if(established_socket->receiver_buffer->allocated_buffer_size == 0)
							{
								if(!established_socket->receiver_buffer->payloads.empty())
								{
									printf("In LAST_ACK, readed data and allocated size is 0 but receiver buffer's payloads is not empty\n");
									return;
								}
								// send FIN(FINACK) packet
								int ip_header_size = 20;
								int tcp_header_size = 20;
								Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + 0);
								//Packet *ack_packet = this->clonePacket(packet);
								PacketManager *finack_packet_manager = new PacketManager(finack_packet);
								finack_packet_manager->setSrcIpAddr(&(established_socket->local_ip_address));
								finack_packet_manager->setSrcPort(&(established_socket->local_port_num));
								finack_packet_manager->setDestIpAddr(&(established_socket->remote_ip_address));
								finack_packet_manager->setDestPort(&(established_socket->remote_port_num));
								unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
								finack_packet_manager->setSeqnum(&seq_num); // we should store appropriate seq num in socket
								//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
								unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
								finack_packet_manager->setAcknum(&ack_num); //we should store appropriate ack num in socket
								uint16_t window_size = htons(51200);
								finack_packet_manager->setWindowSize(&window_size);		
								finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
								finack_packet_manager->setChecksum();
								
								// Set FINACK packet timer
								Packet *clone_sent_packet = this->clonePacket(finack_packet);
								set_system_packet_timer(established_socket, clone_sent_packet, CLOSE_FINACK);
								
								this->sendPacket("IPv4", finack_packet);
								delete finack_packet_manager;
							}

							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}
				
				return;
			}

			else if(established_socket->state == TIMED_WAIT)
			{
				if (established_socket->sender_buffer->allocated_buffer_size == 0)
				{
					if(!established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in TIMED_WAIT state, and sender buffer allocated size is 0 but payloads is not empty\n";
						return;
					}

					// // Case when get ack of FINACK packet
					// // it should remove FINACK timer
					// if(!remove_system_packet_timer(established_socket, CLOSE_FINACK))
					// {
					// 	std::cout<<"received ack packet in LAST_ACK socket, but there's no finack timer\n";
					// 	return;
					// }

					// // free the memory and erase from socket list
					// if(ntohl(*ack_num) == established_socket->seq_num+1 && ntohl(*seq_num) == established_socket->ack_num) //seq num & ack num check
					// {
					// 	// std::cout<<"Connection end. Closing server side. eliminated socket from estalished_socks\n";
					// 	this->established_socks.erase(estab_iter);
					// 	delete established_socket;
					// }
					// return;

					// std::cout<<"It should not exist! Got ack packet in TIMED_WAIT, but it's not data packet's ack\n";
					// return;
				}

				else
				{
					if(established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in TIMED_WAIT state, and sender buffer allocated size is not 0 but payloads is empty\n";
						return;
					}

						if(payload_length==0)
						{
						// Case when get ack of sent data packet
						// Remove data from internal sender buffer
						unsigned long ack_num_h = ntohl(*ack_num);
						uint16_t new_rwnd = 0;
						arrived_packet_manager->getWindowSize(&new_rwnd);
						new_rwnd = ntohs(new_rwnd);
						established_socket->target_rwnd = new_rwnd;
						data_ack_process(ack_num_h, established_socket, new_rwnd, payload_length);

						// Check wheter internal sender buffer is empty. If empty, send the ack of FINACK packet
						if(established_socket->sender_buffer->allocated_buffer_size == 0)
						{
							if(!established_socket->sender_buffer->payloads.empty())
							{
								std::cout<<"Received ack in TIMED_WAIT state, and sender buffer allocated size is 0 but payloads is not empty\n";
								return;
							}
							unsigned long new_ack_num = ntohl(*seq_num)+1;
							unsigned long new_seq_num = ntohl(*ack_num)+1; // why new_seq_num be 2 not 1 in refernce???
							send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
					}
				}

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in TIMED_WAIT, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}
			}

			else if(established_socket->state == CLOSING)
			{
				// if (established_socket->sender_buffer->allocated_buffer_size != 0)
				// {
				// 	if(established_socket->sender_buffer->payloads.empty())
				// 	{
				// 		std::cout<<"Received ack in FIN_WAIT_1 state, and sender buffer allocated size is not 0 but payloads is empty\n";
				// 		return;
				// 	}

				// 	// Case when get ack of sent data packet
				// 	// Remove data from internal sender buffer
				// 	unsigned long ack_num_h = ntohl(*ack_num);
				// 	uint16_t new_rwnd = 0;
				// 	arrived_packet_manager->getWindowSize(&new_rwnd);
				// 	new_rwnd = ntohs(new_rwnd);
				// 	established_socket->target_rwnd = new_rwnd;
				// 	data_ack_process(ack_num_h, established_socket, new_rwnd);

				// 	// Check wheter internal sender buffer is empty. If empty, send the ack of FINACK packet
				// 	if(established_socket->sender_buffer->allocated_buffer_size == 0)
				// 	{
				// 		if(!established_socket->sender_buffer->payloads.empty())
				// 		{
				// 			std::cout<<"Received ack in FIN_WAIT_1 state, and sender buffer allocated size is 0 but payloads is not empty\n";
				// 			return;
				// 		}
				// 		unsigned long new_ack_num = ntohl(*seq_num)+1;
				// 		unsigned long new_seq_num = ntohl(*ack_num)+1; // why new_seq_num be 2 not 1 in refernce???
				// 		send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
				// 	}
				// 	return;
				// }

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in CLOSING, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}

				// change state to TIMED_WAIT and start the timer
				if(ntohl(*ack_num) == established_socket->seq_num && ntohl(*seq_num) == established_socket->ack_num)
				{
					if(!remove_system_packet_timer(established_socket, CLOSE_FINACK))
					{
						std::cout<<"received ack packet in CLOSING socket, but there's no finack timer\n";
						return;
					}

					//std::cout<<"Recieved ACK packet in CLOSING state\n";
					established_socket->state = TIMED_WAIT;
					
					// Set close timer
					struct close_timer_info *close_timer_data = new struct close_timer_info;
					close_timer_data->sock_iter = estab_iter;
					close_timer_data->socket = established_socket;
					Packet *null_packet = NULL;
					Socket *null_socket = NULL;

					TimerInfo *payload = new TimerInfo(null_socket, null_packet, ESTAB_SYN, false, close_timer_data);
					UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(2, TimeUtil::MINUTE));
					// should we make entire timer map (uuid, payload) and add this information into map?
				}
				return;
			}

			else if(established_socket->state == CLOSE_WAIT)
			{
				if ( established_socket->sender_buffer->allocated_buffer_size != 0 )
				{
					if(established_socket->sender_buffer->payloads.empty())
					{
						std::cout<<"Received ack in CLOSE_WAIT state, and sender buffer allocated size is not 0 but payloads is empty\n";
						return;
					}

					// Case when get ack of sent data packet
					// Remove data from internal sender buffer
					unsigned long ack_num_h = ntohl(*ack_num);
					uint16_t new_rwnd = 0;
					arrived_packet_manager->getWindowSize(&new_rwnd);
					new_rwnd = ntohs(new_rwnd);
					established_socket->target_rwnd = new_rwnd;
					data_ack_process(ack_num_h, established_socket, new_rwnd, payload_length);

					// Check wheter internal sender buffer is empty. If empty, send the ack of FINACK packet
					if(established_socket->sender_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->sender_buffer->payloads.empty())
						{
							std::cout<<"Received ack in CLOSE_WAIT state, and sender buffer allocated size is 0 but payloads is not empty\n";
							return;
						}
						unsigned long new_ack_num = ntohl(*seq_num)+1;
						unsigned long new_seq_num = ntohl(*ack_num)+1; // why new_seq_num be 2 not 1 in refernce???
						send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
					}
					return;
				}

				if(established_socket->receiver_buffer->allocated_buffer_size != 0)
				{
					if(payload_length == 0)
					{
						printf("Received ack packet in CLOSE_WAIT, but it's payload length is 0, so it's not data packet\n");
						return;
					}

					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
				}
				return;
			}

			else if(established_socket->state == ESTAB)
			{
				if(remove_system_packet_timer(established_socket, ESTAB_SYNACK))
				{
					// if there was synack_timer, remove it and skip under process since it's for data packet
					return;
				}

				// Getting data packet. But is it ack packet of sent data or data packet?
				unsigned long ack_num_h = ntohl(*ack_num);

				std::map<int, struct packet_unit_payload>::iterator payload_data_iter;
				struct packet_unit_payload found_payload;
				bool found_corr_payload_data = false;
				int acked_payload_num = 0;
				int acked_total_data_length = 0;
				std::map<int, struct packet_unit_payload>::iterator last_payload_iter;
				for(payload_data_iter = established_socket->sender_buffer->payloads.begin(); payload_data_iter != established_socket->sender_buffer->payloads.end(); payload_data_iter++)
				{
					acked_payload_num++;
					acked_total_data_length += payload_data_iter->second.size;
					if((*payload_data_iter).second.start_num + (*payload_data_iter).second.size == ack_num_h )
					{
						found_corr_payload_data = true;
						found_payload = (*payload_data_iter).second;
						last_payload_iter = payload_data_iter;
						break;
					}
				}

				if(!found_corr_payload_data)
				{
					if(payload_length < 0)
					{
						std::cout<<"payload length is smaller than 0!!!\n";
						return;
					}
					else if(payload_length == 0)
					{
						// If received packet's payloads size is 0, then
						// It means it received ack packet for sent packet but there is no such data in internal sender buffer
						// So it might be retransmission of ack packet
						// std::cout<<"payload length is 0 :(\n";

						// (*payload_data_iter).second.start_num + (*payload_data_iter).second.size == ack_num_h 
						// ack_num_h - (*payload_data_iter).second.size == (*payload_data_iter).second.start_num

						if( established_socket->sender_buffer->payloads.begin()->first > ack_num_h )
						{
							std::cout<<"Seems to received ack of data packet and no such info in internal sender buffer, the retransmission, but ack_num is smaller than first one\n";
							return;
						}
						else if(established_socket->sender_buffer->payloads.begin()->first == ack_num_h)
						{
							// received ack_num is equal with first one's start num, so it should be ack retransmission
							// if there is no ack_num in retransmit checker, then this is ther second retransmission
							if(established_socket->fast_retransmit_checker.find(ack_num_h) == established_socket->fast_retransmit_checker.end())
							{
								// established_socket->fast_retransmit_checker.insert(ack_num_h);
								established_socket->fast_retransmit_checker[ack_num_h] = 2;
								// std::cout<<"Second retransmission\n";
								return;
							}
							// if there is ack_num in retransmit checker, then this is third retransmission. Conduct fast retransmission
							else
							{
								established_socket->fast_retransmit_checker[ack_num_h] += 1;

								// # 4 maybe we should change here. To retransmit not once.
								if(established_socket->fast_retransmit_checker.find(ack_num_h)->second > 3)
								{
									// retransmit just once

									// congestion control
									if(established_socket->cg_state == FAST_RECOVERY)
									{
										// change cwnd. cwnd = 1 MSSS
										established_socket->sender_buffer->cwnd += MSS;
										if(established_socket->sender_buffer->cwnd == 0)
											printf("0 case 7\n");

										// send new data if possible
										this->send_data(established_socket);
									}

									return;
								}

								// printf("Fast retransmission of %d\n", ack_num_h);
								// printf("Checker value is  %d\n", established_socket->fast_retransmit_checker[ack_num_h]);

								if (established_socket->data_timers.find(ack_num_h) == established_socket->data_timers.end())
								{
									printf("fast retrnasmitter checker value is %d\n",established_socket->fast_retransmit_checker[ack_num_h]);
									std::cout<<"There's no sent packet data with correspionding seq_num in data_timers list. Something's wrong 2\n";
									printf("data timer is empty? %d\n", established_socket->data_timers.empty());
									established_socket->sender_buffer->cwnd += MSS;
									send_data(established_socket);
									return;
								}

								else if (established_socket->data_timers.find(ack_num_h) != established_socket->data_timers.begin())
								{
									std::cout<<"There's sent packet data with corresponding in data_timers list but it's not first element. Something's wrong\n";
									return;
								}
								
								// reset fast retransmission checker
								// established_socket->fast_retransmit_checker.clear();
								// established_socket->fast_retransmit_checker.erase(ack_num_h);

								// congestion control
								if(established_socket->cg_state == SLOW_START)
								{
									// change ssthresh. ssthesh = cwnd/2
									established_socket->sender_buffer->ssthresh = established_socket->sender_buffer->cwnd/2;
									if(established_socket->sender_buffer->ssthresh == 0)
										printf("ssth 0 case 3\n");

									// change cwnd. cwnd = ssthresh + 3*MSS
									established_socket->sender_buffer->cwnd = established_socket->sender_buffer->ssthresh + 3*MSS;
									if(established_socket->sender_buffer->cwnd == 0)
										printf("0 case 8\n");

									// change state to fast recovery
									established_socket->cg_state = FAST_RECOVERY;
								}
								else if(established_socket->cg_state == CONGESTION_AVOIDANCE)
								{
									// change ssthresh. ssthesh = cwnd/2
									// printf("cwnd value is %d\n", established_socket->sender_buffer->cwnd);
									established_socket->sender_buffer->ssthresh = established_socket->sender_buffer->cwnd/2;
									if(established_socket->sender_buffer->ssthresh == 0)
									{
										printf("ssth 0 case 4\n");
										established_socket->sender_buffer->ssthresh = 1;
									}

									// change cwnd. cwnd = ssthresh + 3*MSS
									established_socket->sender_buffer->cwnd = established_socket->sender_buffer->ssthresh + 3*MSS;
									if(established_socket->sender_buffer->cwnd == 0)
										printf("0 case 9\n");

									// change state to fast recovery
									established_socket->cg_state = FAST_RECOVERY;
								}
								else
								{
									printf("It got normal ack but socket's state is imossible weird state or FAST_RECOVRY\n");
									return;
								}

								// fast retransmission
								for(auto timer_iter = established_socket->data_timers.begin(); timer_iter != established_socket->data_timers.end(); timer_iter++)
								{
									// cancel timer
									this->cancelTimer(timer_iter->second.timer_id);

									// retrnasmit data 
									Packet *stored_packet = timer_iter->second.data_packet;
									if(stored_packet == NULL)
									{
										std::cout<<"stored data packet is NULL\n";
										return;
									}

									Packet *clone_sent_packet = this->clonePacket(stored_packet);
									this->sendPacket("IPv4", stored_packet);

									// set new data packet timer again
									struct close_timer_info *null_cti = NULL;
									TimerInfo *payload = new TimerInfo(established_socket, clone_sent_packet, DATA_SEQ, true, null_cti);
									payload->corr_payload = timer_iter->second.data_packet_payload;
									payload->data_packet_seq_num = timer_iter->second.seq_num;
									UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(100, TimeUtil::MSEC));

									// save newly setted timer's id and packet to send, since we cloned it because sending packet process free the packet
									timer_iter->second.timer_id = timer_id;
									timer_iter->second.data_packet = clone_sent_packet;
								}
								return;
							}
						}
						else
						{
							std::cout<<"Seems to received ack of data packet and no such info in internal sender buffer, the retransmission, but ack_num is larger than first one\n";
							return;
						}
						

						return;
					}

					//std::cout<<"Recieved ACK packet in ESTAB state. But can't find it in sender_buffer's payloads\n";
					
					// If received packet's payloads size is larger than 0, then
					// It menas it received payload data packet from sender side.
					// Receiver side's action should be conducted
					
					// std::cout<<"Receiving process\n";
					
					// unsigned long payload_start_num = 0;
					int seq_num_h = ntohl(*seq_num);
					int ack_num_h = ntohl(*ack_num);

					uint16_t received_checksum = 0;
					arrived_packet_manager->getChecksum(&received_checksum);
					if(received_checksum == 0xEEEE)
					{
						// std::cout<<"Wrong checksum case discard\n";
						// for(int i=0;i<1;i++)
						// {
						// 	unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
						// 	established_socket->ack_num = new_ack_num;
						// 	// unsigned long new_seq_num = (unsigned long)ack_num_h;
						// 	unsigned long new_seq_num = 3131313;
						// 	// established_socket->seq_num = new_seq_num;
						// 	this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						// }
						for(int i=0; i<1; i++)
						{
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
						}
						return;
					}

					if (established_socket->receiver_buffer->initial == true)
					{
						established_socket->receiver_buffer->cursor = ntohl(*seq_num);
						established_socket->receiver_buffer->consecutive_cursor = established_socket->receiver_buffer->cursor + payload_length;
						established_socket->receiver_buffer->initial = false;

						// save data into receiver buffer
						void *received_payload = (char *)malloc(payload_length);
						arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
						// std::cout<<"data process 1\n";
						data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
						return;
					}

					// when it is not initial case, first check received data packet's seq_num is larger than
					// internal receiver buffer's first element's seq_num howabout when it is empty??
					// compare first element's startnum when it is not empty, cursor when it is empty
					// if it is smaller, it might be retransmission.
					// Send ack packet whose ack nun is consecutive cursor
					if(established_socket->receiver_buffer->allocated_buffer_size == 0)
					{
						if(!established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is 0, but payload is not empty\n";
							return;
						}

						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (uint8_t *)malloc(payload_length + 5);
							arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
							// std::cout<<"data process 2\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}

					else
					{
						if(established_socket->receiver_buffer->payloads.empty())
						{
							std::cout<<"Received data packet and receiver buffer's allocated size is not 0, but payload is empty\n";
							return;
						}

						// if(established_socket->receiver_buffer->payloads.begin()->first < seq_num_h)
						if(established_socket->receiver_buffer->cursor <= seq_num_h)
						{
							// save data into receiver buffer
							void *received_payload = (char *)malloc(payload_length + 10);
							arrived_packet_manager->getPayload((uint8_t *)received_payload,static_cast<size_t>(payload_length));
							// std::cout<<"data process 3\n";
							data_process(established_socket, src_ip, dest_ip, src_port, dest_port, ack_num_h, seq_num_h, received_payload, payload_length);
							return;
						}

						else
						{
							// data packet is retransmitted. Send ack packet
							unsigned long new_ack_num = (unsigned long)established_socket->receiver_buffer->consecutive_cursor;
							established_socket->ack_num = new_ack_num;
							unsigned long new_seq_num = (unsigned long)ack_num_h;
							established_socket->seq_num = new_seq_num;
							this->send_packet(established_socket, src_ip, dest_ip, src_port, dest_port, new_ack_num, new_seq_num, 0, 1, 0, false, NULL ,0);
							return;
						}
					}
						
					return;
					// payload_start_num = ntohl(*seq_num);

					// // Check whether internal_receiver_buffer's remained space is enough
					// if(established_socket->receiver_buffer->remained_buffer_size < payload_length)
					// {
					// 	// case flow control failed??
					// 	return;
					// }

					// // if size is enough, add received paylaod into internal receiver buffer
					// void *received_payload = (char *)malloc(payload_length);
					// arrived_packet_manager->getPayload((uint8_t *)received_payload, payload_length);
					// void *payload_buf = (char *)malloc(payload_length);
					// memcpy(payload_buf, received_payload ,payload_length);
					// struct packet_unit_payload each_payload;
					// each_payload.start_num = payload_start_num;
					// each_payload.size = payload_length;
					// each_payload.end_num = each_payload.start_num + each_payload.size-1;
					// each_payload.payload = payload_buf;
					// (established_socket->receiver_buffer->payloads)[each_payload.start_num] = each_payload;

					// //change the size values
					// established_socket->receiver_buffer->remained_buffer_size -= payload_length;
					// established_socket->receiver_buffer->allocated_buffer_size += payload_length;

					// // I think by here, it is okay

					// // check the blocked read syscall
					// if(!established_socket->blocked_syscall.empty())
					// {
					// 	struct blocked_syscall_info blocked_syscall = established_socket->blocked_syscall.front();
					// 	//std::cout<<"check1\n";
					// 	if(blocked_syscall.category == READ_SYSCALL)
					// 	{
					// 		// unblock the blocked read systemcall
					// 		// check whether previous receiver buffer was empty for error checking
					// 		//std::cout<<"check2\n";
					// 		if(established_socket->receiver_buffer->allocated_buffer_size - payload_length != 0)
					// 			{
					// 				// Case when there is blocked read syscall but receiver buffer was not empty before receiving data packet
					// 				std::cout<<"when receiving data packet, remained buffer wasn't empty but read was blocked. blocking is wrong \n";
					// 				return;
					// 			}
					// 		std::cout<<"case 3: unblocking the read syscall\n";
					// 		size_t readed_data = read_internal_receiver_buffer(blocked_syscall.buf, established_socket->receiver_buffer, blocked_syscall.count);
					// 		this->returnSystemCall(blocked_syscall.syscall_id, readed_data);
					// 		established_socket->blocked_syscall.pop_front();
					// 	}
					// }

					// // send ack packet for received packet
					// unsigned long new_ack_num = ntohl(*seq_num)+payload_length;
					// //unsigned long new_ack_num = 0;
					// established_socket->ack_num = new_ack_num;
					// unsigned long new_seq_num = ntohl(*ack_num);
					// established_socket->seq_num = new_seq_num;

					// int ip_header_size = 20;
					// int tcp_header_size = 20;
					// int payload_length_for_sending_ack = 0;
					// Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length_for_sending_ack);
					// PacketManager *ack_packet_manager = new PacketManager(ack_packet);
					// ack_packet_manager->setSrcIpAddr(dest_ip);
					// ack_packet_manager->setSrcPort(dest_port);
					// ack_packet_manager->setDestIpAddr(src_ip);
					// ack_packet_manager->setDestPort(src_port);
					// new_seq_num = htonl(new_seq_num);
					// ack_packet_manager->setSeqnum(&new_seq_num);
					// //unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
					// new_ack_num = htonl(new_ack_num);
					// ack_packet_manager->setAcknum(&new_ack_num);
					// uint16_t window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
					// ack_packet_manager->setWindowSize(&window_size);		
					// ack_packet_manager->setFlag(0, 1, 0);	
					// ack_packet_manager->setChecksum();
					// this->sendPacket("IPv4", ack_packet);
					
					// delete ack_packet_manager;
					// delete received_payload;

					// return;
				}

				// case when get normal ack

				// update rwnd
				uint16_t new_rwnd = 0;
				arrived_packet_manager->getWindowSize(&new_rwnd);
				new_rwnd = ntohs(new_rwnd);
				established_socket->target_rwnd = new_rwnd;

				// reset fast_retransmit_checker (==dup_ack_count == 0 )
				for(auto checker_iter = established_socket->fast_retransmit_checker.begin(); checker_iter != established_socket->fast_retransmit_checker.end();)
				{
					// if (found_payload.start_num >= *checker_iter) # 3
					if (found_payload.start_num >= checker_iter->first)
					{
						// printf("Fast retransmission checker erase case 2, seq_num is %d\n",checker_iter->first);
						checker_iter = established_socket->fast_retransmit_checker.erase(checker_iter);
					}
					else
					{
						checker_iter++;
					}
				}

				last_payload_iter++;
				for(payload_data_iter = established_socket->sender_buffer->payloads.begin(); payload_data_iter != last_payload_iter; payload_data_iter++)
				{
					// turn off the timer
					if(!remove_data_packet_timer(established_socket, payload_data_iter->first))
					{
						return;
					}
						
					// manipulate the buffer size elements
					if(established_socket->sender_buffer->remained_buffer_size + payload_data_iter->second.size <= established_socket->sender_buffer->total_size)
					{
						established_socket->sender_buffer->remained_buffer_size += payload_data_iter->second.size;
						established_socket->sender_buffer->allocated_buffer_size -= payload_data_iter->second.size;
						assert(established_socket->sender_buffer->remained_buffer_size + established_socket->sender_buffer->allocated_buffer_size == established_socket->sender_buffer->total_size);
					}
					else
					{
						printf("sender buffer remained size exceeds the total size!!");
						return;
					}

					// free the data
					delete payload_data_iter->second.payload;
				}

				// remove data from payloads list
				established_socket->sender_buffer->payloads.erase(established_socket->sender_buffer->payloads.begin(), last_payload_iter);

				// unblock the write systemcall
				if(established_socket->sender_buffer->remained_buffer_size > 0)
				{
					if(!established_socket->blocked_syscall.empty())
					{
						struct blocked_syscall_info blocked_syscall = established_socket->blocked_syscall.front();
						if(blocked_syscall.category == WRITE_SYSCALL)
						{
							// unblock the blocked write systemcall
							size_t copied_data = save_internal_sender_buffer(blocked_syscall.buf, established_socket->sender_buffer, blocked_syscall.count);
							this->returnSystemCall(blocked_syscall.syscall_id, copied_data);
							established_socket->blocked_syscall.pop_front();
						}
					}
				}

				// Congestion control
				if(established_socket->cg_state == SLOW_START)
				{
					// change cwnd. cwnd = cwnd + MSS
					established_socket->sender_buffer->cwnd += MSS;
					if(established_socket->sender_buffer->cwnd == 0)
						printf("0 case 10\n");

					// check if cwnd is >= than ssthresh. If satisfies, change state to Congestion Avoidance
					if(established_socket->sender_buffer->cwnd >= established_socket->sender_buffer->ssthresh)
					{
						established_socket->cg_state = CONGESTION_AVOIDANCE;
					}

					// Send new data if possible
					this->send_data(established_socket);
				}
				else if(established_socket->cg_state == CONGESTION_AVOIDANCE)
				{
					// change cwnd. cwnd = cwnd + MSS*(MSS/cwnd)
					// here can be dangerous since total_size is int but MSS/total_size is float
					established_socket->sender_buffer->cwnd += MSS * static_cast<int> (MSS/established_socket->sender_buffer->cwnd);
					if(established_socket->sender_buffer->cwnd == 0)
						printf("0 case 11\n");


					// Send new data if possible
					this->send_data(established_socket);
				}
				else if(established_socket->cg_state == FAST_RECOVERY)
				{
					// change cwnd. cwnd = ssthresh
					established_socket->sender_buffer->cwnd = established_socket->sender_buffer->ssthresh;
					if(established_socket->sender_buffer->cwnd == 0)
						printf("0 case 12\n");

					// change state to congestion avoidance
					established_socket->cg_state = CONGESTION_AVOIDANCE;

					// Since it should not send new data in this case. but i'm not sure...
					return;
				}
				else
				{
					printf("It got normal ack but socket's state is imossible weird state\n");
					return;
				}

				// // Send new data if possible
				// this->send_data(established_socket);
				return;
			}

			else
			{
				std::cout<<"Something's going wrong. Found Established socket and ack for it, but state is none of FIN_WAIT_1, LAST_ACK, CLOSING, TIMED_WAIT\n";
				std::cout<<"socket's state is: "<<established_socket->state<<"\n";
				return;
			}
			return;
		}
		// else
		// {
		// 	std::cout<<"Recived ack packet's crresponding socket is found in no where\n";
		// 	return; //ignore packet
		// }

		// find corresponding listening socket in listeners
		bool listener_find_success = false;
		ListeningSocket *listening_socket = NULL;
		std::list<ListeningSocket *>::iterator listener_iter;
		for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
		{
			// struct in_addr dest_ip_temp;
			// dest_ip_temp.s_addr = *dest_ip;
			// struct in_addr local_ip_temp;
			// local_ip_temp.s_addr = (*listener_iter)->local_ip_address;
			
			// std::cout<<"received_packet's dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
			// std::cout<<"received_packet's dest_port is : "<<ntohs(*dest_port)<<"\n";
			// std::cout<<"listening socket's local_ip is : "<<inet_ntoa(local_ip_temp)<<"\n";
			// std::cout<<"listening socket's local_port is : "<<ntohs((*listener_iter)->local_port_num)<<"\n";
			

			if( ((*listener_iter)->local_ip_address == *dest_ip || (*listener_iter)->local_ip_address == INADDR_ANY) &&
			((*listener_iter)->local_port_num == *dest_port) )
			{
				listening_socket = *listener_iter;
				//listener_iter = this->listeners.erase(listener_iter);
				listener_find_success = true;
				break;
			}
		}

		if(!listener_find_success)
		{
			// // struct in_addr dest_ip_temp;
			// // dest_ip_temp.s_addr = *dest_ip;
			// // struct in_addr src_ip_temp;
			// // src_ip_temp.s_addr = *src_ip;
			// // std::cout<<"received_packet's dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
			// // std::cout<<"received_packet's raw dest_ip is : "<<*dest_ip<<"\n";
			// // std::cout<<"received_packet's h order dest_ip is : "<<ntohl(*dest_ip)<<"\n";
			// // std::cout<<"received_packet's dest_port is : "<<ntohs(*dest_port)<<"\n";
			// // std::cout<<"received_packet's raw dest_port is : "<<*dest_port<<"\n";
			// // std::cout<<"received_packet's src_ip is : "<<inet_ntoa(src_ip_temp)<<"\n";
			// // std::cout<<"received_packet's raw src_ip is : "<<*src_ip<<"\n";
			// // std::cout<<"received_packet's src_port is : "<<ntohs(*src_port)<<"\n";
			// // std::cout<<"received_packet's raw src_port is : "<<*src_port<<"\n";
			// //std::cout<<"Ack packet receivied. there are no corresponding listening socket, and established socket\n";
			// //std::cout<<"\n";

			// for(auto listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
			// {
			// 	struct in_addr local_ip_temp;
			// 	local_ip_temp.s_addr = (*listener_iter)->local_ip_address;
				
			// 	// std::cout<<"listening socket's local_ip is : "<<inet_ntoa(local_ip_temp)<<"\n";
			// 	// std::cout<<"listening socket's local_port is : "<<ntohs((*listener_iter)->local_port_num)<<"\n";
			// 	// std::cout<<"\n";
			// }

			// 	// if( (((*estab_iter)->local_ip_address == *dest_ip || (*estab_iter)->local_ip_address == INADDR_ANY)) &&
			// 	// ((*estab_iter)->local_port_num == *dest_port) &&
			// 	// (((*estab_iter)->remote_ip_address == *src_ip || (*estab_iter)->remote_ip_address == INADDR_ANY)) &&
			// 	// ((*estab_iter)->remote_port_num == *src_port) )

			// std::list<Socket *>::iterator estab_iter_temp;
			// for(estab_iter_temp=this->established_socks.begin(); estab_iter_temp!=this->established_socks.end(); estab_iter_temp++)
			// {
			// 	struct in_addr local_ip_temp;
			// 	local_ip_temp.s_addr = (*estab_iter_temp)->local_ip_address;
			// 	struct in_addr remote_ip_temp;
			// 	remote_ip_temp.s_addr = (*estab_iter_temp)->remote_ip_address;
			// 	// std::cout<<"established socket's local_ip is : "<<inet_ntoa(local_ip_temp)<<"\n";
			// 	// std::cout<<"established socket's raw local_ip is : "<<(*estab_iter_temp)->local_ip_address<<"\n";
			// 	// std::cout<<"established socket's h order local_ip is : "<<ntohl((*estab_iter_temp)->local_ip_address)<<"\n";
			// 	// std::cout<<"established socket's local_port is : "<<ntohs((*estab_iter_temp)->local_port_num )<<"\n";
			// 	// std::cout<<"established socket's raw local_port is : "<<(*estab_iter_temp)->local_port_num<<"\n";
			// 	// std::cout<<"established socket's remote_ip is : "<<inet_ntoa(remote_ip_temp)<<"\n";
			// 	// std::cout<<"established socket's raw remote_ip is : "<<(*estab_iter_temp)->remote_ip_address<<"\n";
			// 	// std::cout<<"established socket's remote_port is : "<<ntohs((*estab_iter_temp)->remote_port_num)<<"\n";
			// 	// std::cout<<"established socket's raw remote_port is : "<<(*estab_iter_temp)->remote_port_num<<"\n";
			// }

			// Check whether there is SYNSENT packet. If there is, in that socket SYANCK timer should be setted
			// if not wierd case
			bool synsent_find_success = false;
			Socket *synsent_socket = NULL;
			std::list<Socket *>::iterator synack_waiters_iter;
			for(synack_waiters_iter = this->con_synack_waiters.begin(); 
			synack_waiters_iter != this->con_synack_waiters.end();
			synack_waiters_iter++)
			{
				if( ((*synack_waiters_iter)->local_ip_address == *dest_ip || (*synack_waiters_iter)->local_ip_address == INADDR_ANY) &&
				((*synack_waiters_iter)->local_port_num == *dest_port) &&
				((*synack_waiters_iter)->remote_ip_address == *src_ip || (*synack_waiters_iter)->remote_ip_address == INADDR_ANY) &&
				((*synack_waiters_iter)->remote_port_num == *src_port))
				{
					synsent_find_success = true;
					synsent_socket = *synack_waiters_iter;
					// case synack is arrived but acknum & seq_num +1 doesn't match should ignore until it comes again
					break;
				}
			}

			if(synsent_find_success)
			{
				if(!remove_system_packet_timer(synsent_socket, ESTAB_SYNACK))
				{
					std::cout<<"Ack packet receivied for synsent socket, but there's no synack timer. Somethings wrong\n";
				}

				//std::cout<<"It recieved synack packet and found in con_synack_waiters, also sent acknum is matched with stored seqnum +1\n";
				this->established_socks.push_back(synsent_socket);
				synsent_socket->state = ESTAB;
				unsigned long new_ack_num = ntohl(*seq_num);
				synsent_socket->ack_num = new_ack_num;
				unsigned long new_seq_num = ntohl(*ack_num);
				synsent_socket->seq_num = new_seq_num;
				synsent_socket->sender_buffer->initial_start_num = new_seq_num;
				synsent_socket->sender_buffer->cursor = new_seq_num;

				struct in_addr dest_ip_temp;
				dest_ip_temp.s_addr = *dest_ip;
				struct in_addr local_ip_temp;
				local_ip_temp.s_addr = synsent_socket->local_ip_address;
				struct in_addr remote_ip_temp;
				remote_ip_temp.s_addr = synsent_socket->remote_ip_address;

				this->returnSystemCall(synsent_socket->syscall_id, 0);
				//return;
			}
			else
			{
				// just other wierd case
				std::cout<<"Ack packet receivied. there are no corresponding listening socket, and established socket, and synsent socket\n";
			}

			return;
		}
		
		// find corresponding pending connection socket in listneing socket's pendint connections list and take it out
		bool synrcvd_find_success = false;
		Socket *synrcvd_socket = NULL;
		std::list<Socket *>::iterator pending_iter;
		for(pending_iter=listening_socket->pending_connections.begin(); 
		pending_iter != listening_socket->pending_connections.end();
		pending_iter++)
		{
			if( ((*pending_iter)->remote_ip_address == *src_ip) &&
			((*pending_iter)->remote_port_num == *src_port) )
			{
				synrcvd_socket = *pending_iter;
				pending_iter = listening_socket->pending_connections.erase(pending_iter);
				synrcvd_find_success = true;
				break;
			}
		}

		if(!synrcvd_find_success)
		{
			std::cout<<"Ack packet receiving failed because there are no corresponding synrcvd socket (no pending connections)\n";
			return;
		}

		if(!remove_system_packet_timer(synrcvd_socket, ESTAB_SYNACK))
			return;

		synrcvd_socket->state = ESTAB;
		synrcvd_socket->seq_num = ntohl(*ack_num); // store new seq_num information in here
		synrcvd_socket->sender_buffer->initial_start_num = synrcvd_socket->seq_num;
		synrcvd_socket->sender_buffer->cursor = synrcvd_socket->seq_num;
		//synrcvd_socket->ack_num += payload length //ack num is not updated because we should consider when first ack packet has payload
		if(listening_socket->accept_requests.empty())
		{
			// There are no existing previous accept reqeusts. Just change it's state
			// and put it to the accepted_connections and wait until accep() syscall is called
			//synrcvd_socket->state = ESTAB_NOT_RETURNED;
			listening_socket->accepted_connections.push_back(synrcvd_socket);
			this->established_socks.push_back(synrcvd_socket);
			return;
		}
		else
		{
			// There is existing previous accept request. so return this synrcvd socket's information
			// for existing accept request.

			// Pop oldes accept request from listening socket's accept_requests list
			struct acceptRequest accept_request = listening_socket->accept_requests.front();
			listening_socket->accept_requests.pop_front();

			// Put synrcvd_socket (now established, and will be return accept syscall) into established connections list
			int new_allocated_fd = this->createFileDescriptor(accept_request.pid);
			synrcvd_socket->fd = new_allocated_fd;
			synrcvd_socket->pid = accept_request.pid;
			//synrcvd_socket->state = ESTAB;
			//listening_socket->established_connections.push_back(synrcvd_socket);
			this->established_socks.push_back(synrcvd_socket);

			// Record remote address(src_ip, port) for accept syscall parameter input
			struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(accept_request.addr);
			addr_in->sin_family = AF_INET;
			addr_in->sin_port = synrcvd_socket->remote_port_num; // or *src_port
			addr_in->sin_addr.s_addr = synrcvd_socket->remote_ip_address; // or *scr_ip

			for(int i=0;i<8;i++)
			{
				addr_in->sin_zero[i] = 0;
			}
			*(accept_request.addrlen) = (socklen_t)sizeof(*(accept_request.addr));

			this->returnSystemCall(accept_request.syscall_id, synrcvd_socket->fd);
			return;
		}
	}

	// 1. Check if arrived packet is synack or not 
	// check here, it was else if
	else if(isSynack(arrived_packet_manager))
	{
		Socket *corr_conn_socket = NULL;

		// Pop corresponding connecting socket in con_synackwiaters
		bool find_success = false;
		bool ack_num_match =false;
		std::list<Socket *>::iterator synack_waiters_iter;
		for(synack_waiters_iter = this->con_synack_waiters.begin(); 
		synack_waiters_iter != this->con_synack_waiters.end();
		synack_waiters_iter++)
		{
			if( ((*synack_waiters_iter)->local_ip_address == *dest_ip || (*synack_waiters_iter)->local_ip_address == INADDR_ANY) &&
			((*synack_waiters_iter)->local_port_num == *dest_port) &&
			((*synack_waiters_iter)->remote_ip_address == *src_ip || (*synack_waiters_iter)->remote_ip_address == INADDR_ANY) &&
			((*synack_waiters_iter)->remote_port_num == *src_port))
			{
				find_success = true;
				//Check wheter arived ack num is right or not
				if( ntohl((*synack_waiters_iter)->seq_num) + 1 == ntohl(*ack_num))
				{
					corr_conn_socket = *synack_waiters_iter;
					synack_waiters_iter = this->con_synack_waiters.erase(synack_waiters_iter);
					ack_num_match =true;
				}
				// case synack is arrived but acknum & seq_num +1 doesn't match should ignore until it comes again
				break;
			}
		}

		// Put found socket into client_established, and call returnSyscall(0)
		if(find_success && ack_num_match) //&& ack_num_match is needed??? (checking ack num)
		{
			// if(!remove_packet_timer(corr_conn_socket, ESTAB_SYN))
			// {

			// 	return;
			// }

			remove_system_packet_timer(corr_conn_socket, ESTAB_SYN);
				
			//std::cout<<"It recieved synack packet and found in con_synack_waiters, also sent acknum is matched with stored seqnum +1\n";
			this->established_socks.push_back(corr_conn_socket);
			corr_conn_socket->state = ESTAB;
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			corr_conn_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num);
			corr_conn_socket->seq_num = new_seq_num;
			corr_conn_socket->sender_buffer->initial_start_num = new_seq_num;
			corr_conn_socket->sender_buffer->cursor = new_seq_num;

			struct in_addr dest_ip_temp;
			dest_ip_temp.s_addr = *dest_ip;
			struct in_addr local_ip_temp;
			local_ip_temp.s_addr = corr_conn_socket->local_ip_address;
			struct in_addr remote_ip_temp;
			remote_ip_temp.s_addr = corr_conn_socket->remote_ip_address;
			// std::cout<<"When putting established sockets, \n";
			// std::cout<<"dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
			// std::cout<<"dest_port is : "<<ntohs(*dest_port)<<"\n";
			// std::cout<<"local ip address of socket is : "<<inet_ntoa(local_ip_temp)<<"\n";
			// std::cout<<"local port of socket is : "<<ntohs(corr_conn_socket->local_port_num)<<"\n";
			// std::cout<<"remote ip address of socket is : "<<inet_ntoa(remote_ip_temp)<<"\n";
			// std::cout<<"remote port of socket is : "<<ntohs(corr_conn_socket->remote_port_num)<<"\n";
			std::list<address_info>::iterator bind_addr_iter;

			// Should send Ack packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;

			// if(remove_packet_timer(corr_conn_socket, ESTAB_SYN))
			this->returnSystemCall(corr_conn_socket->syscall_id, 0);
			return;
		}

		if(!find_success)
		{
			// Check whether packet is in established_socks list
			std::list<Socket*>::iterator estab_iter;
			Socket *established_socket;
			bool find_established = false;
			if(!this->established_socks.empty())
			{
				for(estab_iter=this->established_socks.begin(); estab_iter!=this->established_socks.end(); estab_iter++)
				{				
					if( ((ntohl((*estab_iter)->local_ip_address) == ntohl(*dest_ip) || (*estab_iter)->local_ip_address == INADDR_ANY)) &&
					((*estab_iter)->local_port_num == *dest_port) &&
					(( ntohl((*estab_iter)->remote_ip_address) == ntohl(*src_ip) || (*estab_iter)->remote_ip_address == INADDR_ANY)) &&
					((*estab_iter)->remote_port_num == *src_port) )
					{
						established_socket = *estab_iter;
						find_established = true;
						break;
					}
				}
			}
			if(find_established)
			{
				if(established_socket->state == ESTAB)
				{
					// Case when ack lost, so synack retransmitted. client should send ack packet again
					//but we don't need to set ack timer

					// Retransmit Ack packet
					unsigned long new_ack_num = ntohl(*seq_num)+1;
					established_socket->ack_num = new_ack_num; //should we set ack num again?
					unsigned long new_seq_num = ntohl(*ack_num);
					established_socket->seq_num = new_seq_num; //should we set seq num again?

					int ip_header_size = 20;
					int tcp_header_size = 20;
					int payload_length = 0;
					Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
					PacketManager *ack_packet_manager = new PacketManager(ack_packet);
					ack_packet_manager->setSrcIpAddr(dest_ip);
					ack_packet_manager->setSrcPort(dest_port);
					ack_packet_manager->setDestIpAddr(src_ip);
					ack_packet_manager->setDestPort(src_port);
					new_seq_num = htonl(new_seq_num);
					ack_packet_manager->setSeqnum(&new_seq_num);
					new_ack_num = htonl(new_ack_num);
					ack_packet_manager->setAcknum(&new_ack_num);
					uint16_t window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
					ack_packet_manager->setWindowSize(&window_size);		
					ack_packet_manager->setFlag(0, 1, 0);	
					ack_packet_manager->setChecksum();
					this->sendPacket("IPv4", ack_packet);
					delete ack_packet_manager;

					return;
				}

				else if(established_socket->state == FIN_WAIT_1)
				{
					// Case when ack lost, so synack retransmitted. Client should send ack packet agian, also FINACK packct again too.
					// And FINACK timer's should be reset (remove original one and set new one)

					// Retransmit Ack packet
					unsigned long new_ack_num = ntohl(*seq_num)+1;
					established_socket->ack_num = new_ack_num; //should we set ack num again?
					unsigned long new_seq_num = ntohl(*ack_num);
					established_socket->seq_num = new_seq_num; //should we set seq num again?

					int ip_header_size = 20;
					int tcp_header_size = 20;
					int payload_length = 0;
					Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
					PacketManager *ack_packet_manager = new PacketManager(ack_packet);
					ack_packet_manager->setSrcIpAddr(dest_ip);
					ack_packet_manager->setSrcPort(dest_port);
					ack_packet_manager->setDestIpAddr(src_ip);
					ack_packet_manager->setDestPort(src_port);
					new_seq_num = htonl(new_seq_num);
					ack_packet_manager->setSeqnum(&new_seq_num);
					new_ack_num = htonl(new_ack_num);
					ack_packet_manager->setAcknum(&new_ack_num);
					uint16_t window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
					ack_packet_manager->setWindowSize(&window_size);		
					ack_packet_manager->setFlag(0, 1, 0);	
					ack_packet_manager->setChecksum();
					this->sendPacket("IPv4", ack_packet);
					delete ack_packet_manager;

					// Restransmit FINACK packet
					new_ack_num = established_socket->ack_num;
					new_seq_num = established_socket->seq_num;

					ip_header_size = 20;
					tcp_header_size = 20;
					payload_length = 0;
					Packet *finack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
					PacketManager *finack_packet_manager = new PacketManager(finack_packet);
					finack_packet_manager->setSrcIpAddr(dest_ip);
					finack_packet_manager->setSrcPort(dest_port);
					finack_packet_manager->setDestIpAddr(src_ip);
					finack_packet_manager->setDestPort(src_port);
					//unsigned long seq_num = htonl(established_socket->seq_num); // the seq_num value store in socket is not in network order
					new_seq_num = htonl(new_seq_num);
					finack_packet_manager->setSeqnum(&new_seq_num); // we should store appropriate seq num in socket
					//unsigned long ack_num = htonl(established_socket->ack_num); // the ack_num value store in socket is not in network order
					new_ack_num = htonl(new_ack_num);
					finack_packet_manager->setAcknum(&new_ack_num); //we should store appropriate ack num in socket
					window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
					finack_packet_manager->setWindowSize(&window_size);		
					finack_packet_manager->setFlag(0, 1, 1); // syn, ack, fin
					finack_packet_manager->setChecksum();
					this->sendPacket("IPv4", finack_packet);
					delete finack_packet_manager;

					// should set FINACK timer again

					return;
				}
			}
			else
			{
				std::cout<<"Received synack packet but can't find socket in established_socks, and synsent sockets\n";
				return;
			}
			
		}

		return;
	}

	else if(isFinack(arrived_packet_manager))
	{
		// all cases state are equal or later than ESTAB so find corresponding socket in established_socks list

		// find packet in established_socks list. Their state will be eqaul or later than ESTAB
		std::list<Socket*>::iterator estab_iter;
		Socket *established_socket;
		bool find_established = false;
		if(!this->established_socks.empty())
		{
			for(estab_iter=this->established_socks.begin(); estab_iter!=this->established_socks.end(); estab_iter++)
			{
				struct in_addr src_ip_temp;
				src_ip_temp.s_addr = *src_ip;
				struct in_addr dest_ip_temp;
				dest_ip_temp.s_addr = *dest_ip;
				struct in_addr local_ip_temp;
				local_ip_temp.s_addr = (*estab_iter)->local_ip_address;
				struct in_addr remote_ip_temp;
				remote_ip_temp.s_addr = (*estab_iter)->remote_ip_address;
				// std::cout<<"When searching established sockets FINACK packet arrived, \n";
				// std::cout<<"src_ip is : "<<inet_ntoa(src_ip_temp)<<"\n";
				// std::cout<<"src_port is : "<<ntohs(*src_port)<<"\n";
				// std::cout<<"dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
				// std::cout<<"dest_port is : "<<ntohs(*dest_port)<<"\n";
				// std::cout<<"local ip address of socket is : "<<inet_ntoa(local_ip_temp)<<"\n";
				// std::cout<<"local port of socket is : "<<ntohs((*estab_iter)->local_port_num)<<"\n";
				// std::cout<<"remote ip address of socket is : "<<inet_ntoa(remote_ip_temp)<<"\n";
				// std::cout<<"remote port of socket is : "<<ntohs((*estab_iter)->remote_port_num)<<"\n";

				// std::cout<<((*estab_iter)->local_ip_address == *dest_ip)<<"\n";
				// std::cout<<(*estab_iter)->local_ip_address<<"\n";
				// std::cout<<ntohl((*estab_iter)->local_ip_address)<<"\n";
				// std::cout<<(*dest_ip)<<"\n";
				// std::cout<<ntohl(*dest_ip)<<"\n";
				// std::cout<<((*estab_iter)->local_port_num == *dest_port)<<"\n";
				// std::cout<<((*estab_iter)->remote_ip_address == *src_ip)<<"\n";
				// std::cout<<((*estab_iter)->remote_port_num == *src_port)<<"\n";
				if( (ntohl((*estab_iter)->local_ip_address) == ntohl(*dest_ip) || (*estab_iter)->local_ip_address == INADDR_ANY) &&
				((*estab_iter)->local_port_num == *dest_port) &&
				(((*estab_iter)->remote_ip_address == *src_ip || (*estab_iter)->remote_ip_address == INADDR_ANY)) &&
				((*estab_iter)->remote_port_num == *src_port) )
				{
					established_socket = *estab_iter;
					find_established = true;
					break;
				}
			}
		}

		if(!find_established)
		{
			// std::cout<<"received Finack packet but there is no corresponding socket in established socks list\n";
			// find corresponding listening socket in listeners
			bool listener_find_success = false;
			ListeningSocket *listening_socket = NULL;
			std::list<ListeningSocket *>::iterator listener_iter;

			bool synrcvd_find_success = false;
			Socket *synrcvd_socket = NULL;

			bool accepted_find_success = false;
			Socket *accepted_socket = NULL;
			for(listener_iter=this->listeners.begin(); listener_iter != this->listeners.end() ;listener_iter++)
			{
				if( ((*listener_iter)->local_ip_address == *dest_ip || (*listener_iter)->local_ip_address == INADDR_ANY) &&
				((*listener_iter)->local_port_num == *dest_port) )
				{
					listening_socket = *listener_iter;
					//listener_iter = this->listeners.erase(listener_iter);
					listener_find_success = true;



					// std::list<Socket *>::iterator pending_iter;
					// for(pending_iter=listening_socket->pending_connections.begin(); 
					// pending_iter != listening_socket->pending_connections.end();
					// pending_iter++)
					// {
					// 	if( ((*pending_iter)->remote_ip_address == *src_ip) &&
					// 	((*pending_iter)->remote_port_num == *src_port) )
					// 	{
					// 		synrcvd_socket = *pending_iter;
					// 		//pending_iter = listening_socket->pending_connections.erase(pending_iter);
					// 		synrcvd_find_success = true;
					// 		break;
					// 	}
					// }

					// std::list<Socket *>::iterator accpet_connection_iter;
					// for(accpet_connection_iter=listening_socket->accepted_connections.begin(); 
					// accpet_connection_iter != listening_socket->accepted_connections.end();
					// accpet_connection_iter++)
					// {
					// 	if( ((*accpet_connection_iter)->remote_ip_address == *src_ip) &&
					// 	((*accpet_connection_iter)->remote_port_num == *src_port) )
					// 	{
					// 		accepted_socket = *accpet_connection_iter;
					// 		//pending_iter = listening_socket->pending_connections.erase(pending_iter);
					// 		accepted_find_success = true;
					// 		break;
					// 	}
					// }

					break;
				}
			}

			if(listener_find_success)
			{
				std::cout<<"I failed to find corresponding socket in established socks list, but in listener list!!\n";
				if(synrcvd_find_success)
				{
					std::cout<<"Oh connection list was in pending connection list!!\n";
					return;
				}
				if(accepted_find_success)
				{
					std::cout<<"Wow connection list was in accepted connection list!!\n";
					return;					
				}
				if(!synrcvd_find_success && !accepted_find_success)
				{
					std::cout<<"WTF Only matching listening socket exists there are no connection sockets!!!\n";
					return;					
				}

				return;
			}
			else
			{
				std::cout<<"I coundn't find socket in established_socks, also in listener list :(\n";
				struct in_addr dest_ip_temp;
				dest_ip_temp.s_addr = *dest_ip;
				std::cout<<"Arrived packet info, \n";
				std::cout<<"dest_ip is : "<<inet_ntoa(dest_ip_temp)<<"\n";
				std::cout<<"dest_port is : "<<ntohs(*dest_port)<<"\n";
				std::list<address_info>::iterator bind_addr_iter;
				if(!this->local_addresses.empty())
				{
					for(bind_addr_iter=this->local_addresses.begin(); bind_addr_iter != this->local_addresses.end(); bind_addr_iter++)
					{
						if((*bind_addr_iter).local_ip_address == (*dest_ip)  && (*bind_addr_iter).local_port_num == (*dest_port))
						{
							std::cout<<"However the local address was binded.\n";
							break;
						}
					}
				}
			}
			

			return;
		}

		if(established_socket->state == FIN_WAIT_1)
		{
			// When simultaneous close occured. This host started active close but also get the signal of active close from remote host
			// Change state to CLOSING and send ACK packet for this FIN(FINACK) packet
			established_socket->state = CLOSING;
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num)+1; // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;
			//std::cout<<"Simulatenous close occured. new seq_num value is: "<<new_seq_num<<"\n";

			established_socket->last_ack_num = ntohl(*seq_num);

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at FIN_WAIT_1 but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at FIN_WAIT_1, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at FIN_WAIT_1 but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at FIN_WAIT_1, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			// Send ack of FINACK packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;

			return;
		}

		else if(established_socket->state == ESTAB)
		{
			// When server side of closing is determined. This host should start closing process and wait for passive close(). Sever side
			// Change state to CLOSE_WAIT and send ACK packet for this FIN(FINACK) packet
			// std::cout<<"received FINACK in estab state. Server closing start\n";
			established_socket->state = CLOSE_WAIT;
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num); // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;

			established_socket->last_ack_num = ntohl(*seq_num);

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at ESTAB but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at ESTAB, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at ESTAB but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at ESTAB, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			// Send ack of FINACK packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;

			return;
		}

		else if(established_socket->state == FIN_WAIT_2)
		{
			// When client side of closing received FIN packet. Client side
			// Change state to TIMED_WAIT, send ACK packet and start the timer
			established_socket->state = TIMED_WAIT;

			unsigned long new_ack_num = ntohl(*seq_num)+1;
			//unsigned long new_ack_num = established_socket->ack_num;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num); // why new_seq_num be 2 not 1 in refernce???
			//std::cout<<"client recieved FINACK from server and sendling last ack. new seq_num value is: "<<new_seq_num<<"\n";
			//unsigned long new_seq_num = established_socket->seq_num; // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at FIN_WAIT_2 but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at FIN_WAIT_2, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at FIN_WAIT_2 but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at FIN_WAIT_2, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			// Send ack of FINACK packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;

			// Set close timer
			struct close_timer_info *close_timer_data = new struct close_timer_info;
			close_timer_data->sock_iter = estab_iter;
			close_timer_data->socket = established_socket;
			Packet *null_packet = NULL;
			Socket *null_socket = NULL;

			TimerInfo *payload = new TimerInfo(null_socket, null_packet, ESTAB_SYN, false, close_timer_data);
			UUID timer_id = this->addTimer(payload, TimeUtil::makeTime(2, TimeUtil::MINUTE));
			// should we make entire timer map (uuid, payload) and add this information into map?

			return;
		}

		else if(established_socket->state == TIMED_WAIT)
		{
			// When last ack from client side is lost so server side retransmitted the FIN(FINACK) again. Client side
			// We should retransmit the last ACK packet again

			unsigned long new_ack_num = ntohl(*seq_num)+1;
			//unsigned long new_ack_num = established_socket->ack_num;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num); // why new_seq_num be 2 not 1 in refernce???
			//unsigned long new_seq_num = established_socket->seq_num; // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at TIMED_WAIT but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at TIMED_WAIT, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at TIMED_WAIT but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at TIMED_WAIT, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}
			
			// Send ack of FINACK packet
			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(51200);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;

			return;
		}

		else if(established_socket->state == CLOSE_WAIT)
		{
			// get retransmitted FINACK from client. retransmit the ack
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num); // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at CLOSE_WAIT but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at CLOSE_WAIT, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at CLOSE_WAIT but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at CLOSE_WAIT, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->ack_num < established_socket->last_ack_num)
			{
				std::cout<<"Received FINACK at CLOSE_WAIT, but it didn't read all data\n";
				return;
			}

			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;
		}

		else if(established_socket->state == LAST_ACK)
		{
			// get retransmitted FINACK from client. retransmit the ack
			unsigned long new_ack_num = ntohl(*seq_num)+1;
			established_socket->ack_num = new_ack_num;
			unsigned long new_seq_num = ntohl(*ack_num); // why new_seq_num be 2 not 1 in refernce???
			established_socket->seq_num = new_seq_num;

			if(established_socket->sender_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at LAST_ACK but internal sender buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->sender_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at LAST_ACK, internal sender buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			if(established_socket->receiver_buffer->allocated_buffer_size != 0)
			{
				std::cout<<"Received FINACK at LAST_ACK but internal receiver buffer's allocated size is not 0\n";
				return;
			}

			if(!established_socket->receiver_buffer->payloads.empty())
			{
				std::cout<<"Received FINACK at LAST_ACK, internal receiver buffer's allocated size is 0, but there are someting left in payloads\n";
				return;
			}

			int ip_header_size = 20;
			int tcp_header_size = 20;
			int payload_length = 0;
			Packet *ack_packet = this->allocatePacket(14 + ip_header_size +tcp_header_size + payload_length);
			//Packet *ack_packet = this->clonePacket(packet);
			PacketManager *ack_packet_manager = new PacketManager(ack_packet);
			ack_packet_manager->setSrcIpAddr(dest_ip);
			ack_packet_manager->setSrcPort(dest_port);
			ack_packet_manager->setDestIpAddr(src_ip);
			ack_packet_manager->setDestPort(src_port);
			new_seq_num = htonl(new_seq_num);
			ack_packet_manager->setSeqnum(&new_seq_num);
			//unsigned long new_ack_num = htonl(ntohl(*seq_num)+1);
			new_ack_num = htonl(new_ack_num);
			ack_packet_manager->setAcknum(&new_ack_num);
			uint16_t window_size = htons(established_socket->receiver_buffer->remained_buffer_size);
			ack_packet_manager->setWindowSize(&window_size);		
			ack_packet_manager->setFlag(0, 1, 0);	
			ack_packet_manager->setChecksum();
			this->sendPacket("IPv4", ack_packet);
			delete ack_packet_manager;
		}
	}

	delete arrived_packet_manager;

	delete src_ip;
	delete dest_ip;
	delete src_port;
	delete dest_port; // comsider unsgined long->uint32_t, int (for port num)->uint16_t later
	delete seq_num;
	delete ack_num;
}

void TCPAssignment::timerCallback(void* payload)
{
	TimerInfo *t_info = static_cast<TimerInfo*>(payload);
	// When it's close timer
	if(!t_info->is_packet_timer)
	{
		struct close_timer_info *close_timer_info =  t_info->close_timer_information;
		
		// We should free the memory and eliminate socket from established socket list
		this->established_socks.erase(close_timer_info->sock_iter);
		// std::cout<<"Connection end. eliminated socket from established list\n";
		delete close_timer_info->socket;
		delete close_timer_info;
		delete payload;
		return;	
	}
	// It's packet timer
	else
	{
		if(t_info->category == ESTAB_SYN)
		{
			Packet *stored_packet = t_info->sent_packet;
			if(stored_packet == NULL)
				std::cout<<"stored packet is NULL\n";
			
			Packet *new_stored_packet = this->clonePacket(stored_packet);
			this->sendPacket("IPv4", stored_packet);

			t_info->sent_packet = new_stored_packet;

			if(!remove_system_packet_timer(t_info->socket, t_info->category))
				return;

			set_system_packet_timer(t_info->socket, new_stored_packet, t_info->category);

			// delete t_info->close_timer_information->socket;
			// delete t_info->close_timer_information;
			delete payload;
			return;
		}
		else if(t_info->category == ESTAB_SYNACK)
		{
			Packet *stored_packet = t_info->sent_packet;
			if(stored_packet == NULL)
				std::cout<<"stored packet is NULL\n";
			
			Packet *new_stored_packet = this->clonePacket(stored_packet);
			this->sendPacket("IPv4", stored_packet);

			t_info->sent_packet = new_stored_packet;

			if(!remove_system_packet_timer(t_info->socket, t_info->category))
				return;

			set_system_packet_timer(t_info->socket, new_stored_packet, t_info->category);

			// delete t_info->close_timer_information->socket;
			// delete t_info->close_timer_information;
			delete payload;
			return;
		}
		else if(t_info->category == CLOSE_FINACK)
		{
			Packet *stored_packet = t_info->sent_packet;
			if(stored_packet == NULL)
				std::cout<<"stored packet is NULL\n";
			
			Packet *new_stored_packet = this->clonePacket(stored_packet);
			this->sendPacket("IPv4", stored_packet);

			t_info->sent_packet = new_stored_packet;

			if(!remove_system_packet_timer(t_info->socket, t_info->category))
				return;

			set_system_packet_timer(t_info->socket, new_stored_packet, t_info->category);

			// delete t_info->close_timer_information->socket;
			// delete t_info->close_timer_information;
			delete payload;
			return;
		}
		else if(t_info->category == DATA_SEQ)
		{
			Packet *stored_packet = t_info->sent_packet;
			if(stored_packet == NULL)
				std::cout<<"stored packet is NULL\n";
			
			// retransmit stored data pakcet
			Packet *new_stored_packet = this->clonePacket(stored_packet);
			this->sendPacket("IPv4", stored_packet);

			t_info->sent_packet = new_stored_packet;

			// congestion control
			if(t_info->socket->cg_state == SLOW_START)
			{
				// change ssthresh. ssthesh = cwnd/2
				t_info->socket->sender_buffer->ssthresh = t_info->socket->sender_buffer->cwnd/2;
				if(t_info->socket->sender_buffer->ssthresh == 0)
					printf("ssth 0 case 5\n");

				// change cwnd. cwnd = 1 MSS
				t_info->socket->sender_buffer->cwnd = MSS;
				if(t_info->socket->sender_buffer->cwnd == 0)
					printf("0 case 13\n");
			}
			else if(t_info->socket->cg_state == CONGESTION_AVOIDANCE)
			{
				// change ssthresh. ssthresh = cwnd/2
				t_info->socket->sender_buffer->ssthresh = t_info->socket->sender_buffer->cwnd/2;
				if(t_info->socket->sender_buffer->ssthresh == 0)
					printf("ssth 0 case 6\n");

				// change cwnd. cwnd = 1 MSSS
				t_info->socket->sender_buffer->cwnd = MSS;
				if(t_info->socket->sender_buffer->cwnd == 0)
					printf("0 case 14\n");

				// change state to slow start. But then, it always cwnd and ssthresh value changes to cwnd < ssthresh?
				t_info->socket->cg_state = SLOW_START;
			}
			else if(t_info->socket->cg_state == FAST_RECOVERY)
			{
				// change ssthresh. ssthresh = cwnd/2
				t_info->socket->sender_buffer->ssthresh = t_info->socket->sender_buffer->cwnd/2;
				if(t_info->socket->sender_buffer->ssthresh == 0)
					printf("ssth 0 case 7\n");

				// change cwnd. cwnd = 1 MSSS
				t_info->socket->sender_buffer->cwnd = MSS;
				if(t_info->socket->sender_buffer->cwnd == 0)
					printf("0 case 15\n");

				// change state to slow start
				t_info->socket->cg_state = SLOW_START;
			}
			else
			{
				printf("It got normal ack but socket's state is imossible weird state\n");
				return;
			}

			// set timer again (timer reset)
			if(!remove_data_packet_timer(t_info->socket, t_info->data_packet_seq_num))
				return;

			set_data_packet_timer(t_info->socket, new_stored_packet, t_info->corr_payload, t_info->data_packet_seq_num);

			// Reset fast retransmit checkr. dup ack count = 0
			// t_info->socket->fast_retransmit_checker.clear(); // #2
			if (t_info->socket->fast_retransmit_checker.find(t_info->data_packet_seq_num) != t_info->socket->fast_retransmit_checker.end())
			{
				// printf("Fast retransmission checker erase case 3, seq_num is %d\n",t_info->data_packet_seq_num);
				t_info->socket->fast_retransmit_checker.erase(t_info->data_packet_seq_num);
			}

			delete payload;
			return;
		}
	}
	return;
}


}