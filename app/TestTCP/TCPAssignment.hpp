/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list> //implemented

#include <E/E_TimerModule.hpp>

#define MSS (512)

namespace E
{

//Implemented from here

struct address_info
{
	int fd;
	int pid;
	//struct pid_fd p_fd;
	unsigned long local_ip_address;
	uint16_t local_port_num;
};

struct acceptRequest
{
	UUID syscall_id;
	struct sockaddr *addr;
	socklen_t *addrlen;
	int pid; // for checking using lsiten syscall's pid is right or no, suggest host process of sysall
};

enum socket_state
{
	CLOSED,
	SYNSENT,
	SYNRCVD,
	ESTAB_NOT_RETURNED,
	ESTAB,
	FIN_WAIT_1, //FIN CLIENT STATE
	FIN_WAIT_2, //FIN CLIENT STATE
	TIMED_WAIT, //FIN CLIENT STATE
	CLOSING, //FIN CLIENT STATE, SIMULTANEOUS CLOSE
	CLOSE_WAIT, //FIN SERVER STATE
	LAST_ACK // FIN SERVER STATE
};

enum congestion_state
{
	SLOW_START,
	CONGESTION_AVOIDANCE,
	FAST_RECOVERY
};

class PacketManager
{
	public:
		//int ip_header_size;
		//int tcp_header_size;
		Packet *target_packet;
		size_t paylaod_length;

		PacketManager(Packet *target_packet=NULL)
		{
			//this->ip_header_size = ip_header_size;
			//this->tcp_header_size = tcp_header_size;
			this->target_packet = target_packet;
			this->paylaod_length=0;
		}

		void getSrcIpAddr(unsigned long *ip_addr);
		void getDestIpAddr(unsigned long *ip_addr);
		void setSrcIpAddr(unsigned long *ip_addr);
		void setDestIpAddr(unsigned long *ip_addr);
		void getSrcPort(uint16_t *port_num);
		void getDestPort(uint16_t *port_num);
		void setSrcPort(uint16_t *port_num);
		void setDestPort(uint16_t *port_num);
		void getSeqnum(unsigned long *seq_num);
		void getAcknum(unsigned long *ack_num);
		void setSeqnum(unsigned long *seq_num);
		void setAcknum(unsigned long *ack_num);
		void getFlag(uint16_t *buf);
		void setFlag(int syn, int ack, int fin); //other flags might be consiered for later projects
		void getPayload(uint8_t *buf, size_t length);
		void setPayload(uint8_t *buf, size_t length);
		void setChecksum(void);
		void getWindowSize(uint16_t *window_size);
		void setWindowSize(uint16_t *window_size);

		void getIpLength(uint16_t *ip_size);
		void getChecksum(uint16_t *checksum);
};

enum packet_timer_category
{
	ESTAB_SYN,
	ESTAB_SYNACK,
	ESTAB_ACK,
	DATA_SEQ,
	CLOSE_FINACK,
	CLOSE_ACK,
};
//	DATA_ACK,

struct packet_unit_payload
{
	int start_num;
	int end_num;
	// int expected_receiver_window_size; // #1
	int size;
	void *payload;
	// struct packet_timer_list_elem data_timer;
	//int duplicate_count;
};

struct packet_timer_list_elem
{
	packet_timer_category category;
	UUID timer_id;
	// TimerInfo *payload;
	Packet *data_packet = NULL;
	struct packet_unit_payload *data_packet_payload = NULL;
	int seq_num = 0;
};

class InternalBuffer
{
public:
	std::map<int, struct packet_unit_payload> payloads;
	int total_size;
	int remained_buffer_size;
	int allocated_buffer_size;
	int cursor;

	int initial_start_num;
	bool initial;

	int consecutive_cursor; // for data receiver

	int cwnd; // for data sender
	int ssthresh; // for data sender

	InternalBuffer(size_t total_size)
	{
		this->total_size = total_size;
		this->remained_buffer_size = total_size;
		this->allocated_buffer_size = 0;
		this->cursor = 0;
		this->initial_start_num = 0;
		this->initial = true;

		this->consecutive_cursor = 0;

		this->cwnd = MSS;
		this->ssthresh = 64 * 1024;
	}
};

enum syscall_category
{
	READ_SYSCALL,
	WRITE_SYSCALL
};

class Socket
{
private:

public:
	//struct socket_userinfo userinfo;
	int fd;
	int pid; //host's pid
	//struct pid_fd p_fd;
	unsigned long local_ip_address;
	uint16_t local_port_num;
	unsigned long remote_ip_address;
	uint16_t remote_port_num;
	socket_state state;
	UUID syscall_id;

	unsigned long seq_num;
	unsigned long ack_num;

	unsigned long last_ack_num;

	//struct blocked_syscall_info blocked_syscall;
	std::list<struct blocked_syscall_info> blocked_syscall;
	InternalBuffer *sender_buffer;
	InternalBuffer *receiver_buffer;
	uint16_t target_rwnd;
	// size_t total_read_bytes; //#1

	// int fast_retransmit_checker[3];
	// std::set<int> fast_retransmit_checker;
	std::map<int, int> fast_retransmit_checker;

	std::map<packet_timer_category, struct packet_timer_list_elem> estab_close_timers;
	std::map<int, struct packet_timer_list_elem> data_timers;

	enum congestion_state cg_state;
	bool this_time_send;

	Socket *get_this()
	{
		return this;
	}

	Socket(int pid, int fd, size_t total_sender_buffer_size, size_t total_receiver_buffer_size)
	{
		this->pid = pid;
		this->fd = fd;
		this->local_ip_address=0;
		this->local_port_num=0;
		this->remote_ip_address=0;
		this->remote_port_num=0;
		this->state=CLOSED;
		this->syscall_id=0;

		this->seq_num=0;
		this->ack_num=0;
		
		this->last_ack_num = 0;

		// this->sender_buffer = new InternalBuffer(total_sender_buffer_size);
		this->sender_buffer = new InternalBuffer(51200);
		this->receiver_buffer = new InternalBuffer(total_receiver_buffer_size);
		this->target_rwnd = 51200;
		// this->total_read_bytes = 0; //#1

		// this->fast_retransmit_checker[0] = 0;
		// this->fast_retransmit_checker[1] = 0;
		// this->fast_retransmit_checker[2] = 0;

		this->cg_state = SLOW_START;
		this->this_time_send = true;
	} 

protected:
};

struct close_timer_info
{
	std::list<Socket *>::iterator sock_iter;
	Socket *socket;
};

class TimerInfo
{
	public:
		Packet *sent_packet;
		packet_timer_category category;
		bool is_packet_timer;
		struct close_timer_info *close_timer_information;
		Socket *socket;
		// UUID timer_id;
		struct packet_unit_payload *corr_payload;
		int data_packet_seq_num;

		TimerInfo(Socket *input_socket, Packet *input_packet, packet_timer_category input_category, bool input_is_packet_timer, struct close_timer_info *input_ct_info)
		{
			this->socket = input_socket;
			this->sent_packet = input_packet;
			this->category = input_category;
			this->is_packet_timer = input_is_packet_timer;
			this->close_timer_information = input_ct_info;
			// this->timer_id = timer_uuid;
			this->data_packet_seq_num = 0;
		}
};

struct blocked_syscall_info
{
	syscall_category category;
	UUID syscall_id;
	//Socket *socket;
	void *buf;
	size_t count;
};

class ListeningSocket
{
private:

public:
	int fd;
	int pid;
	//struct pid_fd p_fd;
	unsigned long local_ip_address;
	uint16_t local_port_num;
	std::list<Socket *> pending_connections;
	std::list<Socket *> accepted_connections;
	//std::list<Socket *> established_connections;
	std::list<struct acceptRequest> accept_requests;
	//struct acceptRequest accept_request;
	int backlog;

	unsigned long seq_num; // is this required?
	unsigned long ack_num; // is this required?

	ListeningSocket(int pid, int fd, unsigned long local_ip_address, uint16_t local_port_num, int backlog)
	{
		this->pid = pid;
		this->fd = fd;		
		// this->p_fd.pid = pid;
		// this->p_fd.fd = fd;
		this->local_ip_address=local_ip_address;
		this->local_port_num=local_port_num;
		this->backlog=backlog;

		this->seq_num=0;
		this->ack_num=0;
	} 

protected:
};
//by here

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	//Implemented from here
	std::list<Socket*> unbinded_sockets;
	std::list<Socket*> binded_sockets;
	void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int fd);
	void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	bool check_already_binded(int reqeust_fd, int pid, unsigned long request_ip_addr, uint16_t request_port_num);
	void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	//by here
	//pj2-1
	std::list<Socket *> con_synack_waiters;
	//std::list<Socket *> acc_waiters;
	std::list<ListeningSocket *> listeners;
	//std::list<Socket *> client_established_socks;
	std::list<Socket *> established_socks;
	std::list<struct address_info> local_addresses;
	void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);

	void syscall_write(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count);
	void syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count);
	void send_data(Socket *socket);
	// std::list<struct packet_timer_list_elem> estab_close_timers;

	void set_system_packet_timer(Socket *manager_socket, Packet *clone_sent_packet, packet_timer_category category);
	bool remove_system_packet_timer(Socket *manager_socket, packet_timer_category category);

	void set_data_packet_timer(Socket *manager_socket, Packet *clone_sent_packet, struct packet_unit_payload *packet_payload_data, int seq_num);
	bool remove_data_packet_timer(Socket *manager_socket, int seq_num);

	void data_ack_process(unsigned long ack_num_h, Socket *socket, uint16_t new_rwnd, int payload_length);
	void send_packet(Socket *socket, unsigned long *src_ip, unsigned long *dest_ip, uint16_t *src_port, uint16_t *dest_port, unsigned long new_ack_num, unsigned long new_seq_num, int syn, int ack, int fin, bool is_data_packet, uint8_t *payload ,int payload_length);

	void move_consecutive_cursor(Socket *socket);
	void data_process(Socket *socket, unsigned long *src_ip, unsigned long *dest_ip, uint16_t *src_port, uint16_t *dest_port, int ack_num_h, int seq_num_h, void *received_payload, int payload_length);
	size_t read_internal_receiver_buffer(Socket *socket, uint8_t *target_buf, InternalBuffer *data_buf, int count);

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */