/* utility.c
 * - General Utility Functions
 *
 * Copyright (c) 2003
 * German Federal Agency for Cartography and Geodesy (BKG)
 *
 * Developed for Networked Transport of RTCM via Internet Protocol (NTRIP)
 * for streaming GNSS data over the Internet.
 *
 * Designed by Informatik Centrum Dortmund http://www.icd.de
 *
 * NTRIP is currently an experimental technology.
 * The BKG disclaims any liability nor responsibility to any person or entity
 * with respect to any loss or damage caused, or alleged to be caused,
 * directly or indirectly by the use and application of the NTRIP technology.
 *
 * For latest information and updates, access:
 * http://igs.ifag.de/index_ntrip.htm
 *
 * Georg Weber
 * BKG, Frankfurt, Germany, June 2003-06-13
 * E-mail: euref-ip@bkg.bund.de
 *
 * Based on the GNU General Public License published Icecast 1.3.12
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#ifdef _WIN32
#include <win32config.h>
#else
#include <config.h>
#endif
#endif

#include "definitions.h"
#include <stdio.h>
#include "definitions.h"

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>

#ifndef _WIN32
# include <netdb.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <sys/stat.h>
//# include <sys/file.h>
# include <time.h>
# include <errno.h>
# include <utime.h>
#else
# include <winsock.h>
# include <io.h>
# define access _access
# define open _open
#endif

#include "avl.h"
#include "threads.h"
#include "ntripcaster.h"
#include "ntripcastertypes.h"
#include "ntrip.h"
#include "rtsp.h"
#include "utility.h"
#include "ntripcaster_string.h"
#include "sock.h"
#include "ntripcaster_resolv.h"
#include "sourcetable.h"
#include "match.h"
#include "source.h"
#include "client.h"
#include "admin.h"
#include "commands.h"
#include "avl_functions.h"
#include "log.h"
#include "logtime.h"
#include "main.h"
#include "alias.h"
#include "timer.h"
#include "memory.h"
#include "string.h"
#include "vars.h"
#include "connection.h"
#include "relay.h"
#include "restrict.h"
#include "rtp.h"

#include "authenticate/basic.h" // added. ajd

extern server_info_t info;
static int running;

int password_match(const char *crypted, const char *uncrypted)
{
#ifdef USE_CRYPT
	if(info.encrypt_passwords && strcmp(info.encrypt_passwords, "0"))
	{
		char *test_crypted;
		extern char *crypt(const char *, const char *);

		if (!crypted || !uncrypted)	{
			write_log(LOG_DEFAULT, "ERROR: password_match called with NULL arguments");
			return 0;
		}

		thread_mutex_lock(&info.misc_mutex);
		test_crypted = crypt(uncrypted, crypted);
		if (test_crypted == NULL) {
			thread_mutex_unlock(&info.misc_mutex); // called AFTER write_log before. ajd
			write_log(LOG_DEFAULT, "WARNING - crypt() failed, refusing access");
			return 0;
		}
		if (ntripcaster_strcmp(test_crypted, crypted) == 0)	{
			thread_mutex_unlock(&info.misc_mutex);
			return 1;
		}

		thread_mutex_unlock(&info.misc_mutex);
	}
	else
#endif
	{
		if (!crypted || !uncrypted)	{
			write_log(LOG_DEFAULT, "ERROR: password_match called with NULL arguments");
			return 0;
		}

		if (ntripcaster_strcmp(crypted, uncrypted) == 0)
			return 1;
	}
	return 0;
}

void
print_admin (void *data, void *param)
{
	connection_t *con = (connection_t *)data;
	admin_t *admin;
	sock_t *sock = NULL;
	char buf[BUFSIZE], timebuf[BUFSIZE];

	if (!data)
	{
		xa_debug (1, "DEBUG: print_admin() called with NULL pointer");
		return;
	}
	
	admin = con->food.admin;
	if (param)
		sock = (sock_t *)param;
	else return;

	snprintf (buf, BUFSIZE, "Admin %ld\t[%s] connected for %s. %d commands issued.\tFlags:", con->id, 
		 con_host (con), nntripcaster_time (get_time () - con->connect_time, timebuf), admin->commands);
	
	sock_write (*sock, "%s", buf);
	flags2string (admin, param);
	if (thread_equal (thread_self (), con->food.admin->thread)) sock_write (*sock, " - It's you! -");
	sock_write_line (*sock, "");
}

void
print_connection (void *data, void *param)
{
	char buf[BUFSIZE], timebuf[BUFSIZE];
	connection_t *con = (connection_t *)data;
	sock_t *sock = NULL;
	char *type;

	if (param)
		sock = (sock_t *)param;
	else return;

	if (con->type == source_e)
		type = "source";
	else if (con->type == client_e)
		type = "client";
	else if (con->type == admin_e)
		type = "admin";
	else
		type = "unknown";

	snprintf (buf, BUFSIZE, "%ld\t [%s] connected for %s. Type: [%s]\r\n", con->id, con_host (con), 
		 nntripcaster_time (get_time () - con->connect_time, timebuf), type);

	sock_write (*sock, "%s", buf);
}

/* Print one single source, without audiocast data 
   when param is NULL, output to statsfile */
void 
print_source(void *data, void *param)
{
	connection_t *con = (connection_t *)data;
	source_t *source;
	sock_t *sock = NULL;
	char buf[BUFSIZE], timebuf[BUFSIZE];

	source = con->food.source;
	if (param)
		sock = (sock_t *)param;
	else
		return;
	
	snprintf (buf, BUFSIZE, "Source %ld\t[%s] connected for %s, %lu KBytes transfered, type: %s, streaming to %lu clients.\r\n",
		 con->id, con_host (con), nntripcaster_time (get_time() - con->connect_time, timebuf), 
		 source->stats.read_kilos, source_type(con),
		 source->num_clients);
	
	sock_write (*sock, "%s", buf);
}

/* Print one single source, without audiocast data 
   when param is NULL, output to statsfile */
void 
print_source_verbose (void *data, void *param)
{
	connection_t *con = (connection_t *)data;
	source_t *source;
	sock_t *sock = NULL;
	char buf[BUFSIZE], /* buf2[2 * BUFSIZE],*/ timebuf[BUFSIZE];
//	relay_id_t *rip;
//	avl_traverser trav = {0};
	
	source = con->food.source;
	if (param)
		sock = (sock_t *)param;
	else return;
	
	snprintf (buf, BUFSIZE, "Source %lu\t[%s] connected for %s, %lu KBytes transfered",
		 con->id, con_host (con), nntripcaster_time (get_time() - con->connect_time, timebuf), source->stats.read_kilos);
/*
	if (source->dumpfile)
	{
		snprintf (buf2, BUFSIZE, "%sdumping to [%s]\r\n", buf, source->dumpfile);
		strncpy (buf, buf2, BUFSIZE);
	} else {
		strcat (buf, "not dumping to any file\r\n");
	}
*/

	sock_write (*sock, "%s", buf);

/*
	snprintf (buf, BUFSIZE, "\tStream Title: %s\r\n\tStream URL: %s\tx-audiocast-name: %s\r\n\tx-audiocast-genre: %s\r\n\tx-audiocast-bitrate: %d\r\n\tx-audiocast-url: %s\r\n\tx-audiocast-mount: %s\r\n\tx-audiocast-description: %s\r\n\tx-audiocast-public: %d\r\n",
		 source->info.streamtitle ? source->info.streamtitle : "n/a", source->info.streamurl ? source->info.streamurl : "n/a",
		 source->audiocast.name, source->audiocast.genre, source->audiocast.bitrate, source->audiocast.url, 
		 source->audiocast.mount, source->audiocast.description, source->audiocast.public);
*/
	
	sock_write (*sock, "%s", buf);
/*
	if (!param)
		fd_write (info.statsfile, "\tdirectory servers: ");
	else
		sock_write (*sock, "\tdirectory servers: ");
*/
/*
	while ((rip = avl_traverse (source->relay_tree, &trav)))
	{
		if (!param)
			fd_write (info.statsfile, "%s:%d ", rip->host, rip->id);
		else
			sock_write (*sock, "%s:%d ", rip->host, rip->id);
	}
*/
	sock_write (*sock, "\r\n");
		
}

/*
void 
print_clients(void *data, void *param)
{
	connection_t *con = (connection_t *)data;
	
	if (param)
	{
		sock_write_line (*((sock_t *)param), "--- Source ---");
		print_source (con, param);
		sock_write_line (*((sock_t *)param), "--- Listeners ---");
	} else {
		fd_write (info.statsfile, "--- Source ---\n");
		print_source (con, param);
		fd_write (info.statsfile, "--- Listeners ---\n");
	}

	thread_mutex_lock (&con->food.source->mutex);
	avl_walk (con->food.source->clients, print_client, param);
	thread_mutex_unlock (&con->food.source->mutex);
}
*/

void 
print_client(void *data, void *param)
{
	connection_t *con = (connection_t *)data;
	client_t *client;
	sock_t *sock = NULL;
	char buf[BUFSIZE], timebuf[BUFSIZE];

	if (param)
		sock = (sock_t *) param;
	else return;
	
	client = con->food.client;
	
	snprintf (buf, BUFSIZE, "Client %ld\t[%s] connected for %s, %lu bytes transfered. %d errors. User agent: [%s]. Type: %s\r\n",
		 con->id, con_host (con), nntripcaster_time (get_time () - con->connect_time, timebuf), client->write_bytes, client_errors (client), 
		 get_user_agent (con), client_type(con));

	sock_write (*sock, "%s", buf);
}

/*
void 
print_directory (void *data, void *param)
{
	directory_server_t *dir = (directory_server_t *)data;
	sock_t *sock;

	if (param) {
		sock = (sock_t *)param;
		if (dir->type == icy_e)
			sock_write_line (*sock, "Server: [%s] id: [%d] touches: [%d]", dir->host, dir->id, dir->counter);
		else
			sock_write_line (*sock, "Server: [%s:%d%s] id: [%d] touches: [%d]", dir->host, dir->port, dir->path, dir->id, dir->counter);
	}
}
*/

int 
field_ok (char *xac, char *field)
{
	if (!field || !field[0])
	  {
	    write_log (LOG_DEFAULT, "Header is missing %s field", xac);
	    return 0;
	  }

	return 1;
}
/*
int find_frame_ofs(source_t *source)
{
	char *buff;
	int pos = 0, cid;
	
	if (!source)
	{
		write_log (LOG_DEFAULT, "ERROR: find_frame_ofs() called with NULL argument");
		return 0;
	}

	if (info.use_meta_data)
	  return 0;

	cid = source->cid <= 0 ? CHUNKLEN - 1 : source->cid - 1;
	
	buff = source->chunk[cid].data;
	
	while (pos < source->chunk[cid].len - 1) {
		if ((buff[pos] & 0xFF) == 0xFF && (buff[pos + 1] & 0xF0) == 0xF0)
			break;
		pos++;
	}
	
	return pos;
}
*/

void
kick_connection_not_me (void *conarg, void *reasonarg)
{
	connection_t *kickcon = (connection_t *)conarg;
	
	if (kickcon->type == admin_e)
	{
		if (thread_equal (kickcon->food.admin->thread, thread_self ()))
			return;
	} else if (kickcon->type == source_e)
	{
		if (thread_equal (kickcon->food.source->thread, thread_self ()))
			return;
	}
	kick_connection (conarg, reasonarg);
}
		
void
kick_connection(void *conarg, void *reasonarg)
{
	connection_t *con = (connection_t *)conarg;
	char *reason = (char *)reasonarg;

	char timebuf[BUFSIZE] = "";

	if (!conarg || !reasonarg) {
		write_log (LOG_DEFAULT, "WARNING: kick_connection called with NULL pointers");
		return;
	}
	
	switch (con->type) {
		case client_e:
			write_log (LOG_DEFAULT, 
				   "Kicking client %d [%s] [%s] [%s], connected for %s on mountpoint [%s], %lu bytes transfered. %d clients connected",
				   con->id, con_host (con), reason, client_type(con),
				   nntripcaster_time (get_time () - con->connect_time, timebuf),
				   con->food.client->source->audiocast.mount, // added. ajd
				   con->food.client->write_bytes, info.num_clients - 1);
			con->food.client->alive = CLIENT_DEAD;
			if(con->udpbuffers)
			{
				con->rtp->datagram->pt = 98;
				sock_write_string_con(con, "");
			}

/*			if (con->food.client->type == pusher_e) {
				relay_t *rel = relay_find_with_con (con);
				if (rel) {
					rel->con = NULL;
					rel->reconnect_now = 1;
				}
				else
					write_log (LOG_DEFAULT, "WARNING: Pushing relay was not found in the list of relays");
			}
*/			
			write_clf (con, con->food.client->source);
			return;
			break;
		case admin_e:
			write_log (LOG_DEFAULT, "Kicking admin %d [%s] [%s], %d commands issued, connected for %s. %d admins connected",
				   con->id, con_host (con), reason, con->food.admin->commands, 
				   nntripcaster_time (get_time () - con->connect_time, timebuf), info.num_admins - 1);
				   
			sock_close(con->sock); // in free_con() the socket is closed, too. ajd
			con->sock = -1; // added. ajd
			con->food.admin->alive = 0;
			return;
			break;
		case source_e:
		        {
		        	int num;
				thread_mutex_lock(&info.source_mutex);
				num = (con->food.source->connected == SOURCE_UNUSED) ? info.num_sources : info.num_sources - 1;
				thread_mutex_unlock(&info.source_mutex);
				write_log (LOG_DEFAULT, 
				   "Kicking source %d [%s] [%s] [%s], connected for %s on mountpoint [%s], %lu bytes transfered. %d sources connected",
				   con->id, con_host (con), reason, source_type(con),
				   nntripcaster_time (get_time () - con->connect_time, timebuf),
				   con->food.source->audiocast.mount,
				   con->food.source->stats.read_bytes, num);
			}
			if(con->udpbuffers)
			{
				con->rtp->datagram->pt = 98;
				sock_write_string_con(con, "");
			}
			if (con->food.source->connected == SOURCE_UNUSED) {
//				write_log (LOG_DEFAULT, "!!!!!!!!!!!!! SOURCE_UNUSED !!!!!!!!!!!!!!"); // ajd

/* added locking. don't use it, cause a pulling relay is a source and locks
the double_mutex itself before => deadlock may occur. ajd

thread_mutex_lock(&info.double_mutex);
thread_mutex_lock(&info.source_mutex);
thread_mutex_lock(&con->food.source->mutex);
*/
//write_log(LOG_DEFAULT, "sourceunused:1");
				close_connection (con);
//write_log(LOG_DEFAULT, "sourceunused:2");
/*
thread_mutex_unlock(&con->food.source->mutex);
thread_mutex_unlock(&info.source_mutex);
thread_mutex_unlock(&info.double_mutex);
*/

			} else {
				/* Let the source kill itself */
				if(con->sock >= 0)
					sock_close(con->sock); // in free_con() the socket is closed, too. ajd
				con->sock = -1; // added. ajd
				con->food.source->connected = SOURCE_KILLED;
			}

			return;
			break;
		default:
			write_log(LOG_DEFAULT, "Kicking unknown %d [%s] [%s], connected for %s", con->id, con_host (con), reason, 
				  nntripcaster_time (get_time () - con->connect_time, timebuf));
			break;
	}
	close_connection(con);
	return;
}

/*
directory_server_t *create_directory()
{
	directory_server_t *dir = nmalloc(sizeof(directory_server_t));
	dir->counter = 0;
	dir->touches = 0;
	dir->id = -1;
	dir->host = NULL;
	dir->port = -1;
	dir->path = NULL;
	return dir;
}
*/

/*
void close_directory(void *data, void *param)
{
	directory_server_t *dir = (directory_server_t *)data;

	if (dir->id >= 0 && dir->type == icy_e)
		directory_remove (dir);
	avl_delete(info.d_servers, dir);
	nfree(dir->host);
	nfree(dir->path);
	nfree(dir);
}
*/

connection_t *
get_admin_with_id(int id)
{
	connection_t con;
	connection_t *res;

	con.type = admin_e;
	con.id = id;
	res = avl_find(info.admins, &con);
	return res;
}

void
free_con (connection_t *con)
{
	if (con->sock >= 0)
	{
		if (!(con->host && ntripcaster_strcmp (con->host, "NtripCaster console") == 0)) {	
			sock_close (con->sock);
			con->sock = -1;
		}
	}

	if (con->host != NULL)
	{
		nfree(con->host);
		con->host = NULL;
	}

	if (con->headervars != NULL)
		free_con_variables (con);
		
	if (con->sin != NULL)
		nfree (con->sin);
	
	if (con->hostname != NULL)
	{
		nfree(con->hostname);
		con->hostname = NULL;
	}

	if (con->group != NULL) { // added. ajd
		nfree(con->group);
		con->group = NULL;
	}

	/* rtsp. ajd */
	if (con->rtp != NULL) {
		rtp_free(con->rtp);
		nfree (con->rtp);
		con->rtp = NULL;
	}
	if (con->http_chunk != NULL) {
		nfree (con->http_chunk);
		con->http_chunk = NULL;
	}
	if (con->udpbuffers != NULL) {
		thread_mutex_destroy(&con->udpbuffers->buffer_mutex);
		nfree (con->udpbuffers);
		con->udpbuffers = NULL;
	}
}

/* Must have the mutex when calling this:
   admin: must have info.admin_mutex
   client: must have the current source mutex
   source: must have its own mutex, and info.source_mutex */
void 
close_connection(void *data)
{
	connection_t *con = (connection_t *)data;
	
	if (!con) {
		write_log(LOG_DEFAULT, "ERROR: close_connection called with null pointer!");
		return;
	}
	
	xa_debug (2, "DEBUG: Removing connection %d of type %d", con->id, con->type);

	if (con->type == admin_e) {
		xa_debug (2, "Removing admin %d (%p) from admintree of (%p)", con->id, con, info.admins);
		del_admin();
		avl_delete (info.admins, con);

		free_con (con); /* Free:s stuff that all connections have */
		nfree (con->food.admin);
		nfree (con);
		return;
	} else if (con->type == client_e) {
		if (con->food.client->source != NULL) {
			con->food.client->source->stats.client_connect_time += (unsigned long)((get_time () - con->connect_time) / 60.0);
			thread_mutex_lock (&info.misc_mutex); // added. ajd
			info.hourly_stats.client_connect_time += (unsigned long)((get_time() - con->connect_time) / 60.0);
			thread_mutex_unlock (&info.misc_mutex); // added. ajd

			xa_debug (2, "DEBUG: Removing client %d (%p) from sourcetree of (%p)", con->id, con, con->food.client->source);

			if (!avl_delete(con->food.client->source->clients, con)) xa_debug (2, "DEBUG: Didn't find client in sourcetree!");

			if (con->food.client->virgin == 0)
				del_client (con, con->food.client->source);
			else
				util_decrease_total_clients();
		}

		remove_group_connection(con); // if groupmember signs off, number of allowed group connection is increased. ajd

		if (con->food.client->type != rtsp_client_e) {
			thread_mutex_lock (&info.client_mutex);
			avl_delete (info.clients, con);
			thread_mutex_unlock (&info.client_mutex);
		}

		rtsp_remove_connection_from_session(con, con->session_id); // rtsp. ajd

		free_con (con); /* Free:s stuff that all connections have */
		nfree (con->food.client);
		nfree (con);
		return;
	} else if (con->type == source_e) {
		source_t *source = con->food.source;
		connection_t *clicon;

		if (!source)
		{
			write_log (LOG_DEFAULT, "WARNING!!! - Erroneous source without food");
			return;
		}

		xa_debug (2, "Removing source %d (%p) from sourcetree of (%p)", con->id, con, info.sources);

		if (source->clients != NULL) // was (source && source->clients). ajd
		{
			avl_traverser trav = {0};

			if(source->num_clients)
				write_log(LOG_DEFAULT, "Kicking all %d clients for source %d", source->num_clients, con->id);
			while ((clicon = avl_traverse (source->clients, &trav))) kick_connection (clicon, "Stream ended");

			kick_dead_clients (source);

			if (con->food.source->type == pulling_source_e) {
				relay_t *rel;

#ifdef CHANGE1
				// ????????
//				if (source->connected != SOURCE_KILLED && source->connected != SOURCE_UNUSED &&
//				    source->connected != SOURCE_PENDING) {
				thread_mutex_lock (&info.relay_mutex);  // was thread_mutex. DEADLOCK, because thread_mutex_lock:get_my thread locks it too. ajd
				rel = relay_find_with_con (con);
				if (rel) {
					rel->con = NULL;
					rel->pending = 0;
				}
				thread_mutex_unlock (&info.relay_mutex);
//				} else 
//					rel = relay_find_with_con (con);
#else
				/* ???????? */
				if (source->connected != SOURCE_KILLED && source->connected != SOURCE_UNUSED &&
				    source->connected != SOURCE_PENDING) {
					thread_mutex_lock (&info.relay_mutex);  // was thread_mutex. DEADLOCK, because thread_mutex_lock:get_my thread locks it too. ajd
					rel = relay_find_with_con (con);
					thread_mutex_unlock (&info.relay_mutex);
				} else 
					rel = relay_find_with_con (con);

				if (rel) rel->con = NULL;
#endif
			}
			
			avl_destroy (source->clients, NULL);
		}

		dispose_audiocast (&source->audiocast);

		info.hourly_stats.source_connect_time += ((get_time () - con->connect_time) / 60);

		if (con->food.source->connected != SOURCE_UNUSED)
		{
			del_source();
			avl_delete (info.sources, con);
		}

//		if (source->source_agent != NULL) nfree(source->source_agent); // added. ajd

		rtsp_remove_connection_from_session(con, con->session_id); // rtsp. ajd

		free_con (con); /* Free:s stuff that all connections have */
		nfree(source);
		nfree(con);
		return;
	} else {
		free_con (con); /* Free:s stuff that all connections have */
		nfree(con); /* Unknown connection, still remove con */
		return;
	}
}

void
kick_not_connected (connection_t *con, char *reason)
{
	char timebuf[BUFSIZE];
	char typebuf[10];

	if (reason) write_log (LOG_DEFAULT, "Kicking %s %d [%s] [%s], connected for %s", type_of_str (con->type, typebuf), con->id, con_host (con), reason, nntripcaster_time (get_time () - con->connect_time, timebuf));

	free_con (con);

	if (con->type == source_e) {
//		  avl_destroy (con->food.source->relay_tree, NULL);
		  avl_destroy (con->food.source->clients, NULL);
		  nfree (con->food.source);
	} else if (con->type == client_e) {
		nfree (con->food.client);
	}
	else if (con->type == admin_e) {
		nfree (con->food.admin);
	}

	nfree (con);
}

void
kick_silently (connection_t *con)
{
	free_con (con);
	
	nfree (con);
}
	

source_t *
source_with_client(connection_t *con)
{
	if (con)
		return (con->food.client->source);
	return NULL;
}  

#ifndef _WIN32
int server_detach()
{
	pid_t icepid;

	write_log(LOG_DEFAULT, "Trying to fork");

	icepid = fork();
	if (icepid == -1) {
		write_log(LOG_DEFAULT, "ERROR: Can't fork dammit!");
		return 1;
	}
  
	if (icepid != 0) {
#ifdef HAVE_SETPGID
		write_log(LOG_DEFAULT, "Detached (pid: %d)", icepid);
		setpgid(icepid, icepid);
#endif
		exit(0);
	} else {
#ifdef HAVE_SETPGID
		setpgid(0, 0);
#endif
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);
		fd_close(0);
		fd_close(1);
		fd_close(2);
	}
	return 1;
}
#endif

connection_t *
find_con_with_host (const struct sockaddr_in *sin)
{
	connection_t *clicon;
	avl_traverser clitrav = {0};
	char hbuf[BUFSIZE];
	char *hostptr;

	if (!sin)
		return NULL;

	hostptr = makeasciihost(&sin->sin_addr, hbuf);

	thread_mutex_lock (&info.client_mutex);
	
	while ((clicon = avl_traverse (info.clients, &clitrav)))
	{
		if (clicon->host && clicon->sin && (ntripcaster_strcasecmp (clicon->host, hostptr) == 0) &&
		    clicon->sin->sin_port == sin->sin_port)
		{
			thread_mutex_unlock (&info.client_mutex);
			return clicon;
		}
	}

	thread_mutex_unlock (&info.client_mutex);
	
	return NULL;
}

connection_t *
find_con_with_host_and_udpport (const char *hostptr, const int portnr)
{
	connection_t *clicon;
	avl_traverser clitrav = {0};

	thread_mutex_lock (&info.client_mutex);
	
	while ((clicon = avl_traverse (info.clients, &clitrav)))
	{
		if (((clicon->host && ntripcaster_strcasecmp (clicon->host, hostptr) == 0)
		     || (clicon->hostname && ntripcaster_strcasecmp (clicon->hostname, hostptr) == 0))
		    && (clicon->sin->sin_port == htons (portnr)))
		{
			thread_mutex_unlock (&info.client_mutex);
			return clicon;
		}
	}

	thread_mutex_unlock (&info.client_mutex);
	
	return NULL;

}

connection_t *
find_client_with_id (int id)
{
	connection_t con, *res = NULL;
	con.id = id;
	con.type = client_e;

	thread_mutex_lock (&info.client_mutex);
	res = avl_find (info.clients, &con);
	thread_mutex_unlock (&info.client_mutex);

	return res;
}

connection_t *
find_source_with_id (int id)
{
	connection_t con, *res;
	con.id = id;
	con.type = source_e;

	thread_mutex_lock (&info.source_mutex);
	res = avl_find (info.sources, &con);
	thread_mutex_unlock (&info.source_mutex);
	return res;
}

connection_t *
find_source_with_mount (char *mount)
{
	avl_traverser trav = {0};
	connection_t *scon = NULL;

	thread_mutex_lock (&info.source_mutex);
	
	while ((scon = avl_traverse (info.sources, &trav))) {
		if (ntripcaster_strcmp (mount, scon->food.source->audiocast.mount) == 0)
			break;
	}
	
	thread_mutex_unlock (&info.source_mutex);
	
	return scon;
}
	
/* Try to avoid this function if at all possible, 
   since it's locking stuff all over the place */
connection_t *
find_id (int id)
{
  avl_traverser trav = {0};
  connection_t *con;
  
  thread_mutex_lock (&info.admin_mutex);
  while ((con = avl_traverse (info.admins, &trav)))
    {
      if (con->id == (unsigned)id)
	{
	  thread_mutex_unlock (&info.admin_mutex);
	  return con;
	}
    }
  thread_mutex_unlock (&info.admin_mutex);

  zero_trav (&trav);

  thread_mutex_lock (&info.source_mutex);

  while ((con = avl_traverse (info.sources, &trav)))
    {
      if (con->id == (unsigned)id)
	{
		thread_mutex_unlock (&info.source_mutex);
		return con;
	}
    }
    
  thread_mutex_unlock (&info.source_mutex);   

  zero_trav (&trav);
  
  thread_mutex_lock (&info.client_mutex);

  while ((con = avl_traverse (info.clients, &trav)))
    {
	if (con->id == (unsigned)id)
	    {
		thread_mutex_unlock (&info.client_mutex);
		return con;
	    }
    }
 
  thread_mutex_unlock (&info.client_mutex);
  return NULL;
}
	
void
kick_everything ()
{
  connection_t *con, *con2;
  
  while ((con = avl_get_any_node (info.sources)))
  {
	  while ((con2 = avl_get_any_node (con->food.source->clients)))
		  kick_connection (con2, "Masskick by admin");
	  kick_connection (con, "Masskick by admin");
  }

  while ((con = avl_get_any_node (info.admins)))
	  kick_connection (con, "Masskick by admin");
  
  return;
}

void
kick_if_match (char *pattern)
{
	char buf[BUFSIZE];
	snprintf (buf, BUFSIZE, "Matching %s", pattern);
	do_if_match_all (pattern, kick_connection, buf, 1);
}

void
do_if_match_all (char *pattern, avl_node_func func, void *buf, int destructive)
{
  thread_mutex_lock (&info.admin_mutex);
  do_if_match_tree (info.admins, pattern, func, buf, destructive);
  thread_mutex_unlock (&info.admin_mutex);

  thread_mutex_lock (&info.client_mutex);
  do_if_match_tree (info.clients, pattern, func, buf, 0);
  thread_mutex_unlock (&info.client_mutex);

  thread_mutex_lock (&info.source_mutex);
  /* Nothing can be destructive with sources */
  do_if_match_tree (info.sources, pattern, func, buf, 0);
  thread_mutex_unlock (&info.source_mutex);

}

void
do_if_match_tree_destructive (avl_tree *tree, char *pattern, avl_node_func func, void *buf)
{
	avl_traverser trav = {0};
	connection_t *con;
	
	xa_debug (2, "Destructively traversing tree (%p) with %s", tree, pattern);

	zero_trav (&trav);

	while (42)
	{
		con = avl_traverse (tree, &trav);
		if (!con)
			break;
		if (wild_match ((unsigned char *)pattern, (unsigned char *)con->host) 
		    || (con->hostname && (wild_match ((unsigned char *)pattern, (unsigned char *)con->hostname))))
		{
			if (con->type == admin_e && thread_equal (con->food.admin->thread, thread_self ()))
				xa_debug (2, "DEBUG: Skipping myself in destructive tree traversal");
			else
			{
				xa_debug (3, "%s matched, starting over", con->host);
				(func)(con, buf);
				zero_trav (&trav); /* Start over */
			}
		}
	}
}

void
do_if_match_tree (avl_tree *tree, char *pattern, avl_node_func func, void *buf, int destructive)
{
	avl_traverser trav = {0};
	connection_t *con;

	if (destructive)
		do_if_match_tree_destructive (tree, pattern, func, buf);
	else
	{
		while ((con = avl_traverse (tree, &trav)))
		{
			if (wild_match ((unsigned char *)pattern, (unsigned char *)con->host) 
			    || (con->hostname && wild_match ((unsigned char *)pattern, (unsigned char *)con->hostname)))
				(func)(con, buf);
		}
	}
}

  
unsigned long int
new_id ()
{
	unsigned long int ret;
	thread_mutex_lock (&info.misc_mutex);
	ret = info.id;
	info.id++;
	thread_mutex_unlock (&info.misc_mutex);
	return ret;
}

void
kill_threads ()
{
	avl_traverser trav = {0};
	connection_t *con;
	mythread_t *mt;

	write_log (LOG_DEFAULT, "Telling threads to die...");

	internal_lock_mutex (&info.thread_mutex);
	/* Go through all threads, kill them off */
	while ((mt = avl_traverse (info.threads, &trav))) {
		mt->running = THREAD_KILLED;
	}
	
	internal_unlock_mutex (&info.thread_mutex);
	
	write_log (LOG_DEFAULT, "Closing sockets for admins that keep hanging around...");
	/* First all admins */
	thread_mutex_lock (&info.double_mutex);
	thread_mutex_lock (&info.admin_mutex);

	while ((con = avl_traverse (info.admins, &trav))) {
		if (!(con->host && ntripcaster_strcmp (con->host, "NtripCaster console") == 0))
			sock_close(con->sock);
	}

	thread_mutex_unlock (&info.admin_mutex);
	thread_mutex_unlock (&info.double_mutex);
	
	write_log (LOG_DEFAULT, "Closing sockets for sources that keep hanging around...");
	
	zero_trav (&trav);
	
	/* Then all sources */
	thread_mutex_lock (&info.source_mutex);
	while ((con = avl_traverse (info.sources, &trav))) {
		sock_close(con->sock);
		con->food.source->connected = SOURCE_KILLED;
	}
	
	thread_mutex_unlock (&info.source_mutex);
}

time_t
tree_time(avl_tree *tree)
{
	connection_t *con;
	avl_traverser trav = {0};
	time_t t, tc = 0;
	
	t = get_time();
	while ((con = avl_traverse(tree, &trav)))
		tc += (t - con->connect_time);
	return tc / 60;
}
		
void 
write_ntripcaster_header ()
{
	printf("NtripCaster Version %s Initializing...\n", info.version);
	printf("NtripCaster comes with NO WARRANTY, to the extent permitted by law.\nYou may redistribute copies of NtripCaster under the terms of the\nGNU General Public License.\nFor more information about these matters, see the file named COPYING.\n");
	printf("Starting thread engine...\n");
	//write_log(LOG_DEFAULT, "NtripCaster Version %s Starting..", info.version); // removed. ajd
}

void
print_startup_server_info ()
{
	int i;

	if (info.myhostname && ntripcaster_strcmp (info.myhostname, "0.0.0.0"))
		write_log(LOG_DEFAULT, "Listening on host %s...", info.myhostname);

	for (i = 0; i < MAXLISTEN; i++) {
		if (info.port[i] > 0)
			write_log(LOG_DEFAULT, "Listening on port %i...", info.port[i]);
	}

	if (info.server_name)
		write_log (LOG_DEFAULT, "Using '%s' as servername...", info.server_name);

	write_log(LOG_DEFAULT, "Server limits: %d clients, %d clients per source, %d sources, %d admins", 
		  info.max_clients, info.max_clients_per_source, info.max_sources, info.max_admins);

	if (info.allow_http_admin)
		write_log (LOG_DEFAULT, "WWW Admin interface accessible at http://%s:%d/admin", info.server_name, info.port[0]);
	else
		write_log (LOG_DEFAULT,  "Access to WWW Admin interface disabled");
}

void
sanity_check ()
{
	int fd = -1;
	char *file = get_log_file (info.logfilename);
	char template_file[BUFSIZE];

	if (!file)
	{
		write_log (LOG_DEFAULT, "ERROR: Could not find a suitable directory for server logfiles");
		fprintf (stderr, "ERROR: Could not find a suitable directory for server logfiles\n");
		clean_resync (&info);
	}

	xa_debug (1, "DEBUG: Checking write access for file %s", file);
	if ((fd = open_for_append (file)) == -1) // use append, don't overwrite existing logfile!!! ajd
	{
		write_log (LOG_DEFAULT, "Could not write log file [%s]. Exiting.", file);
		fprintf (stderr, "Could not write log file [%s]. Exiting.\n", file);
		clean_resync (&info);
	} else {
		fd_close (fd);
//remove (file);
	}

	nfree (file);

	if (get_ntripcaster_file ("home.html", template_file_e, R_OK, template_file) == NULL)
	{
		write_log (LOG_DEFAULT, "ERROR: Could not find a suitable directory for template files, something might be wrong!");
		return;
	}

	xa_debug (1, "DEBUG: Looking for templates");

	if ((fd = open_for_reading (template_file)) == -1)
	  {
	    write_log (LOG_DEFAULT, "WARNING: Could not find template file for mountlist.html, something might be wrong!");
	    fd_close (fd);
	  }
	
//	nfree (file);
}

unsigned long int
transfer_average (unsigned long int bytes, unsigned long int connections)
{
	if (!connections)
		return bytes;
	return (unsigned long int)((double) bytes / (double) connections);
}

char *
connect_average (unsigned long int minutes, unsigned long int connections, char *buf)
{
	if (!connections)
		return nntripcaster_time_minutes (minutes, buf);
	return nntripcaster_time_minutes ((unsigned long int)((double) minutes  / (double) connections), buf);
}


int
hostname_local (char *name)
{
	char *new;

	if (!name)
	{
		write_log (LOG_DEFAULT, "ERROR: hostname_local called with NULL name");
		return 0;
	}

	if (!name[0])
		return 1;

	if (ntripcaster_strcasecmp (name, "localhost") == 0 || ntripcaster_strcasecmp (name, "127.0.0.1") == 0)
		return 1;
	if (info.server_name && ntripcaster_strcasecmp (name, info.server_name) == 0)
		return 1;
	if (info.myhostname && ntripcaster_strcasecmp (name, info.myhostname) == 0)
		return 1;

	/* Search the tree */
	thread_mutex_lock (&info.hostname_mutex);
	
	new = avl_find (info.my_hostnames, name);

	thread_mutex_unlock (&info.hostname_mutex);

	if (new)
		return 1;

	/* Not in the tree, try to reverse it */
	{
		char buf[BUFSIZE], *out;
		char *res = forward (name, buf);

		if (!res)
			return 0; /* Unresolvable */
			
		thread_mutex_lock (&info.hostname_mutex);

		out = avl_find (info.my_hostnames, res);
		
		thread_mutex_unlock (&info.hostname_mutex);

		if (out || (info.myhostname && (ntripcaster_strcasecmp (res, info.myhostname) == 0)) || (ntripcaster_strcmp (res, "127.0.0.1") == 0))
		{
			thread_mutex_lock (&info.hostname_mutex);
			avl_insert (info.my_hostnames, nstrdup (name));
			thread_mutex_unlock (&info.hostname_mutex);
			return 1;
		}
	}
	return 0;
}

/* to parse a HTTP conform or NTRIP1.0 specific request. rtsp. ajd */
void build_request (connection_t *con, char *line, ntrip_request_t *req) {
	char path[BUFSIZE];
	char meth[BUFSIZE];
	char *ptr, *lineptr;
	int protocol = unknown_protocol_e;

	if (!line || !req) {
		write_log (LOG_DEFAULT, "ERROR: build_request called with NULL pointer");
		return;
	}

	xa_debug (2, "DEBUG: Building request out of [%s]", line);

	if (splitc(meth, line, ' ') == NULL) {
		xa_debug (1, "DEBUG: Build request called with invalid line [%s]", line);
		return;
	}

	/* assume line now consists of either
	   "/path"
	   "HTTP/1.0"

	   "/path HTTP/1.0"
	   "http://somewhat.com/path HTTP/1.0"
	   "http://somewhat.com:8000/path HTTP/1.0"
	   "http://somewhat.com:8000 HTTP/1.0"

	   or

	   "password /path" (method SOURCE)
	   "password" (method ADMIN)
	*/

	if ((strncmp(meth, "SOURCE", 6) == 0) || (strncmp(meth, "ADMIN", 5) == 0)) {

		if (splitc(path, line, ' ') != NULL) {
			add_varpair2(con->headervars, nstrdup("Authorization"), nstrdup(clean_string(path)));

			if (line[0] == '/')
				lineptr = &line[0]+1;
			else
				lineptr = &line[0];
			snprintf(req->path, BUFSIZE, "/%s", lineptr);
		} else
			add_varpair2(con->headervars, nstrdup("Authorization"), nstrdup(clean_string(line)));

		if (info.server_name)
			strncpy(req->host, info.server_name, BUFSIZE);
		else
			strncpy(req->host, "localhost", BUFSIZE);

		req->port = info.port[0];
	} else {
		if (splitc(path, line, ' ') == NULL) {
			if (line[0] == '/') {
				strncpy (req->path, line, BUFSIZE);
			} else {
				xa_debug (1, "Empty request [%s]", line);
				strncpy (req->path, "/", BUFSIZE);
			}

			if (info.server_name)
				strncpy (req->host, info.server_name, BUFSIZE);
			else
				strncpy (req->host, "localhost", BUFSIZE);
			req->port = info.port[0];
			protocol = http_e;
		} else {
			if ((strncmp(path, "http://", 7) == 0) || (strncmp(path, "rtsp://", 7) == 0)) {
				lineptr = &path[7];

				xa_debug (2, "DEBUG: Building request from [%s]", lineptr);

				if (splitc(req->host, lineptr, '/') == NULL) {
					strncpy (req->host, lineptr, BUFSIZE);
					*lineptr = '\0';
				}

				ptr = strchr (req->host, ':');

				if (ptr) /* port present */
				{
					*ptr = '\0';
					req->port = atoi (ptr+1);
				} else {
					req->port = info.port[0];
				}
			} else {
			
				xa_debug (2, "DEBUG: Building request from [%s]", path);
			
				if (path[0] == '/')
					lineptr = &path[0]+1;
				else
					lineptr = &path[0];
	
				if (info.server_name)
					strncpy (req->host, info.server_name, BUFSIZE);
				else
					strncpy (req->host, "localhost", BUFSIZE);
	
				req->port = info.port[0];
			}
			snprintf(req->path, BUFSIZE, "/%s", lineptr);
	
			if (strncmp(line, "HTTP", 4) == 0)
				protocol = http_e;
			else if (strncmp(line, "RTSP", 4) == 0)
				protocol = rtsp_e;
	
			xa_debug (2, "DEBUG: req->path = [%s], req->port = %d, protocol = %d", req->path, req->port, protocol);
		}
	}

	req->method = get_ntrip_method(meth, protocol); // rtsp. ajd
}

/*
void
build_request (char *line, request_t *req)
{
	char path[BUFSIZE] = "";
	char *ptr, *lineptr;

	if (!line || !req)
	{
		write_log (LOG_DEFAULT, "ERROR: build_request called with NULL pointer");
		return;
	}

	xa_debug (2, "DEBUG: Building request out of [%s]", line);

	if (ntripcaster_strncmp (line, "GET", 3) == 0)
	{

		splitc (NULL, line, ' ');
		// Now we've got either:
		//   "/ HTTP/1.0"
		//   "HTTP/1.0"
		//   "http://whatever.com/ HTTP/1.0"
		//   "http://whatever.com:8000/ HTTP/1.0"
		//   "http://whatever.com:8000 HTTP/1.0"


		if ((splitc (path, line, ' ') == NULL) || !path[0] || path[0] == ' ')
		{
			xa_debug (1, "Empty GET request [%s]", line);
			strncpy (req->path, "/", BUFSIZE);
			strncpy (req->host, info.server_name, BUFSIZE);
			req->port = info.port[0];
			return;
		}

		if (ntripcaster_strncmp (path, "http://", 7) == 0)
		{
			lineptr = &path[7];

			xa_debug (2, "DEBUG: Building http request from [%s]", lineptr);

			ptr = strchr (lineptr, ':');
			
			if (ptr) // port present
			{
				splitc (req->host, lineptr, ':');
				req->port = atoi (lineptr);

				lineptr = strchr (lineptr, '/');
				
				if (!lineptr)
					strncpy (req->path, "/", BUFSIZE);
				else
				{
					if (splitc (req->path, lineptr, ' ') == NULL)
						strncpy (req->path, lineptr, BUFSIZE);
				}
				return;
			} else {
				req->port = info.port[0];

				ptr = strchr (lineptr, '/');

				if (!ptr)
				{
					if (splitc (req->host, lineptr, ' ') == NULL)
						strncpy (req->host, lineptr, BUFSIZE);
					strncpy (req->path, "/", BUFSIZE);
					return;
				} else {
					if (splitc (req->host, lineptr, '/') == NULL)
						strncpy (req->host, lineptr, BUFSIZE);
					else if (splitc (req->path, lineptr, ' ') == NULL)
						strncpy (req->path, lineptr, BUFSIZE);

					if (req->path[0] != '/')
						strncpy (req->path, "/", BUFSIZE);
					return;
				}
			}

		} else {
			char pathbuf[BUFSIZE];

			xa_debug (2, "DEBUG: Building clean request from [%s]", path);

			req->port = info.port[0];
			if (splitc (pathbuf, path, ' ') == NULL)
				strncpy (pathbuf, path, BUFSIZE);

			if (pathbuf[0] == '/')
				strncpy (req->path, pathbuf, BUFSIZE);
			else
				snprintf (req->path, BUFSIZE, "/%s", pathbuf);

			if (info.server_name)
				strncpy (req->host, info.server_name, BUFSIZE);
			else
				strncpy (req->host, "localhost", BUFSIZE);
			return;
		}
		
	} else if ((ntripcaster_strncmp (line, "HOST:", 5) == 0) || (ntripcaster_strncmp (line, "Host:", 5) == 0))
	{
		char hostbuf[BUFSIZE] = "";

		splitc (NULL, line, ':');

		while (*line == ' ')
			line++;

		ptr = strchr (line, ':');

		if (ptr)
		{
			splitc (hostbuf, line, ':');
			req->port = atoi (line);
		} else {
		    if (splitc (hostbuf, line, ' ') == NULL) strncpy (hostbuf, line, BUFSIZE);
		}
		
		strncpy (req->host, hostbuf, BUFSIZE);

		return;
	} else {
		xa_debug (1, "DEBUG: Build request called with invalid line [%s]", line);
	}
}
*/


/* now must have source_mutex to call this. ajd */	
connection_t *
mount_exists (char *mount)
{
	avl_traverser trav = {0};
	connection_t *scon;

	//thread_mutex_lock (&info.source_mutex);

	while ((scon = avl_traverse (info.sources, &trav)))
	{
		if ((ntripcaster_strcmp (mount, scon->food.source->audiocast.mount) == 0)/* && (scon->food.source->connected != SOURCE_PENDING)*/)
		{
			//thread_mutex_unlock (&info.source_mutex);
			return scon;
		}
	}

	//thread_mutex_unlock (&info.source_mutex);

	return NULL;
}

void
generate_request (char *line, ntrip_request_t *req)
{
	char full[BUFSIZE];

	if (!line || !req)
	{
		write_log (LOG_DEFAULT, "ERROR: generate_request called with NULL pointer");
		return;
	}

	snprintf (full, BUFSIZE, "GET %s HTTP/1.0", line);

	build_request (NULL, full, req);

	if (req->path[0])
		xa_debug (2, "DEBUG: Generated request [%s:%d%s]", req->host, req->port, req->path);

}

void
generate_http_request (char *line, ntrip_request_t *req)
{
	char full[BUFSIZE + 50] = "";
	
	if (!line || !req)
	{
		write_log (LOG_DEFAULT, "ERROR: generate_request called with NULL pointer");
		return;
	}

	if (ntripcaster_strncmp (line, "http://", 7) == 0)
	{
		snprintf (full, BUFSIZE, "GET %s HTTP/1.0", line);
	} else {
		snprintf (full, BUFSIZE, "GET http://%s HTTP/1.0", line);
	}

	build_request (NULL, full, req);

	xa_debug (2, "DEBUG: Generated http request [%s:%d%s]", req->host, req->port, req->path);
}

void
zero_request (ntrip_request_t *req) {
	req->method = NULL;
	req->path[0] = '\0';
	req->host[0] = '\0';
//	req->user[0] = '\0';
	req->port = -1;
	req->cseq = -1;
	req->sessid = -1;
}

char *
next_mount_point ()
{
	avl_traverser trav = {0};
	connection_t *sourcecon;
	static char apan[30];
	int count = 0;

	while ((sourcecon = avl_traverse (info.sources, &trav)))
	{
		if (ntripcaster_strncmp (sourcecon->food.source->audiocast.mount, "/icy_", 5) == 0 && (sourcecon->food.source->connected != SOURCE_PENDING))
			count++;
	}

	snprintf (apan, sizeof(apan), "icy_%d", count);

	return &apan[0];
}

void init_thread_tree(int line, char *file)
{
	mythread_t *mt;
	
	if (!file) {
		fprintf (stderr, "WARNING: init_thread_tree() called with file == NULL\n");
		exit (1);
	}

	info.threads = NULL;
	info.threadid = 0;

	mt  = (mythread_t *)malloc(sizeof(mythread_t)); // was nmalloc. ajd

	/* Create a tree for all threads */
	info.threads = avl_create(compare_threads, &info);

	/* Some luxury just to make the main thread show up in com_threads() */
	mt->id = 0;
	mt->line = line;
	mt->file = strdup(file);
	mt->thread = thread_self();
	mt->created = get_time();
	mt->name = strdup("Main Thread");

	if (avl_insert(info.threads, mt)) {
		fprintf (stderr, "WARNING: Could not insert main thread into the thread tree, DAMN!\n");
		exit(1);
	}
	
	thread_create_mutex(&info.thread_mutex);

	/* On platforms where it is supported, this enables this thread to be
	   cancelable */
	thread_init();

	thread_catch_signals ();

	thread_setup_default_attributes();

#ifdef DEBUG_MEMORY
	info.mem = avl_create_nl(compare_mem, &info);
	thread_create_mutex (&info.memory_mutex);
#endif
}

void
pending_connection (connection_t *con)
{
	// write_log (LOG_DEFAULT, "Lost connection to source on mount %s, waiting %d seconds for timeout", con->food.source->audiocast.mount, info.client_timeout);
	con->food.source->connected = SOURCE_PENDING;

	/* Get the relay reconnector to reconnect this source */
	if (con->food.source->type == pulling_source_e) {
		relay_t *rel;
		thread_mutex_lock (&info.relay_mutex);
		rel = relay_find_with_con (con);
		if (rel) {
			rel->con = NULL;
			rel->reconnect_now = 1;
		} /* It is an alias.. don't reconnect */
		thread_mutex_unlock (&info.relay_mutex);
	}
}

int
pending_source_signoff (connection_t *con)
{
	time_t start = get_time ();
	while (is_server_running() && con->food.source->connected == SOURCE_PENDING && ((get_time () - start) < info.client_timeout))
		sleep_random(1);  // was "my_sleep(90000);". ajd
	if (con->food.source->connected == SOURCE_PENDING)
		return 1;
	return 0;
}
		
connection_t *
get_pending_mount (char *mount)
{
	avl_traverser trav = {0};
	connection_t *sourcecon;

	thread_mutex_lock (&info.source_mutex);

	while ((sourcecon = avl_traverse (info.sources, &trav)))
	{
		if ((ntripcaster_strcmp (sourcecon->food.source->audiocast.mount, mount) == 0) && (sourcecon->food.source->connected == SOURCE_PENDING))
		{
			thread_mutex_unlock (&info.source_mutex);
			return sourcecon;
		}
	}

	thread_mutex_unlock (&info.source_mutex);
	return NULL;
}

/*
void clear_source_stats (void *data, void *param)
{
        connection_t *con = (connection_t *)data;
        source_t *source;
        source = con->food.source;
	thread_mutex_lock(&source->mutex);         
	zero_stats (&source->stats);
	avl_walk (source->clients, clear_client_stats, param);
	thread_mutex_unlock(&source->mutex);
}

void clear_client_stats (void *data, void *param)
{
	connection_t *con = (connection_t *)data;
        client_t *client;
        client = con->food.client;
	client->write_bytes = 0;
}

void clear_admin_stats (void *data, void *param)
{
	connection_t *con = (connection_t *)data;
        admin_t *admin;
	admin = con->food.admin;
	admin->commands = 0;
}
*/

int
hosteq (connection_t *con, connection_t *con2)
{
	if (con->host && con2->host)
	{
		if (ntripcaster_strcasecmp (con->host, con2->host) == 0)
			return 1;
	}
	
	if (con->hostname && con2->hostname)
	{
		if (ntripcaster_strcasecmp (con->hostname, con2->hostname) == 0)
			return 1;
	}

	return 0;
}

int
hostmatch (const connection_t *con, const char *pattern)
{
	if (!pattern || !con)
		return 0;
	if (con->host && wild_match ((unsigned char *)pattern, (unsigned char *)con->host))
		return 1;
	if (con->hostname && wild_match((unsigned char *)pattern, (unsigned char *)con->hostname))
		return 1;
	return 0;
}

int
open_for_writing (const char *filename)
{
  int fd;

  if (!filename)
	  return -1;
  
  fd = open (filename, O_WRONLY|O_CREAT|O_TRUNC, 02644); // to prepare the file for mandatory locking (was 00644). ajd
  if (fd == -1)
    xa_debug (1, "ERROR: Cannot open file for writing[%s]", filename);
  return fd;
}

int open_for_reading(const char *filename)
{
	int fd;

	if (!filename) {
		xa_debug(1, "ERROR: Cannot open file for reading no file specified");
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd == -1) xa_debug(1, "ERROR: Cannot open file for reading [%s]", filename);

	return fd;
}

int
open_for_append (const char *filename)
{
  int fd;

  if (!filename) return -1;

  fd = open (filename, O_WRONLY|O_APPEND|O_CREAT, 02644); // to prepare the file for mandatory locking (was 00644). ajd
  
  if (fd == -1) {
  	xa_debug (1, "ERROR: Cannot open file for append [%s]", filename);
  	return fd;
  }
  
  return fd;
}

/*
int
lock_file (int fd) {
	struct flock fl;
//	int flags;

	fl.l_type   = F_WRLCK;  // F_RDLCK, F_WRLCK, F_UNLCK    
	fl.l_whence = SEEK_SET; // SEEK_SET, SEEK_CUR, SEEK_END 
	fl.l_start  = 0;        // Offset from l_whence         
	fl.l_len    = 0;        // length, 0 = to EOF           
	fl.l_pid    = getpid(); // our PID                      
	
//	flags = fcntl(fd, F_GETFL);
//	printf("!!!!!!!!!!STATUSFLAGS: %d\r\n", flags);

	return fcntl(fd, F_SETLK, &fl);  // F_GETLK, F_SETLK, F_SETLKW
}

int
unlock_file (int fd) {
	struct flock fl;

	fl.l_type   = F_UNLCK;  // F_RDLCK, F_WRLCK, F_UNLCK    
	fl.l_whence = SEEK_SET; // SEEK_SET, SEEK_CUR, SEEK_END 
	fl.l_start  = 0;        // Offset from l_whence         
	fl.l_len    = 0;        // length, 0 = to EOF           
	fl.l_pid    = getpid(); // our PID                      

	return fcntl(fd, F_SETLK, &fl);  // F_GETLK, F_SETLK, F_SETLKW 
}
*/

/*
char *
get_template (const char *filename)
{
noch was
	return get_ntripcaster_file (filename, template_file_e, R_OK);
}
*/

char *
get_log_file (const char *filename) 
{
	char logdir[BUFSIZE];
	char filenamedate[BUFSIZE];
#ifdef DAILY_LOGFILES
	char date[50];
#endif

	if (!filename || !info.logdir) {
		fprintf (stderr, "WARNING: get_log_file() called with NULLs\n");
		return NULL;
	}

#ifdef DAILY_LOGFILES
//*** added. ajd
	get_short_date(date);
	snprintf (filenamedate, BUFSIZE, "%s-%s.log", filename, date);

//	if (filename == info.accessfilename) {
//		snprintf (logdir, BUFSIZE, "%s%c", info.acsdir, DIR_DELIMITER);
//		xa_debug (1, "DEBUG: Checking directory %s", logdir);
//		if (access (info.acsdir, R_OK) == 0) return ntripcaster_cat (logdir, filenamedate);
//	}
//***
#else
	snprintf (filenamedate, BUFSIZE, "%s.log", filename);
#endif

	snprintf (logdir, BUFSIZE, "%s%c", info.logdir, DIR_DELIMITER);
	xa_debug (1, "DEBUG: Checking directory %s", logdir);

	if (access (info.logdir, R_OK) == 0) {
		return ntripcaster_cat (logdir, filenamedate);
	}

	snprintf (logdir, BUFSIZE, "log%c", DIR_DELIMITER);
	xa_debug (1, "DEBUG: Checking directory %s", logdir);
	
	if (access (logdir, R_OK) == 0) {
		return ntripcaster_cat (logdir, filenamedate);
	}

	snprintf (logdir, BUFSIZE, "%s%c", ".", DIR_DELIMITER);
	
	if (access (logdir, R_OK) == 0) {
		return ntripcaster_cat (logdir, filenamedate);
	}

	return NULL;
}

char *
get_ntripcaster_file(const char *filename, filetype_t type, int flags, char *path_and_file)
{
//	char path_and_file [BUFSIZE];

	if (!filename || !info.etcdir || !info.logdir || !info.templatedir || !info.vardir) {
		xa_debug(1, "ERROR: get_ntripcaster_file(): called with NULL pointer");
		return NULL;
	}

	if(filename[0] == '/')
	{
		strncpy(path_and_file, filename, BUFSIZE);
		if (access(path_and_file, flags) == 0)
			return path_and_file;
		return NULL;
	}

	path_and_file[0] = '\0';

	switch (type) {
		case conf_file_e:
			snprintf(path_and_file, BUFSIZE, "%s%c%s", info.etcdir, DIR_DELIMITER, filename);
			break;
		case log_file_e:
			snprintf(path_and_file, BUFSIZE, "%s%c%s", info.logdir, DIR_DELIMITER, filename);
			break;
		case template_file_e:
			snprintf(path_and_file, BUFSIZE, "%s%c%s", info.templatedir, DIR_DELIMITER, filename);
			break;
		case var_file_e:
			snprintf(path_and_file, BUFSIZE, "%s%c%s", info.vardir, DIR_DELIMITER, filename);
			break;
/*
		case static_file_e:
			snprintf(path_and_file, BUFSIZE, "%s%c%s", info.staticdir, DIR_DELIMITER, filename);
			break;
*/
		default:
			snprintf(path_and_file, BUFSIZE, "%s", filename);
	}

	xa_debug(3, "DEBUG: get_ntripcaster_file(): Looking for %s", path_and_file);

	if (access(path_and_file, flags) == 0)
		return path_and_file;
	
	switch (type) {
		case conf_file_e:
			snprintf(path_and_file, BUFSIZE, ".%c%s%c%s", DIR_DELIMITER, "conf", DIR_DELIMITER, filename);
			break;
		case log_file_e:
			snprintf(path_and_file, BUFSIZE, ".%c%s%c%s", DIR_DELIMITER, "logs", DIR_DELIMITER, filename);
			break;
		case template_file_e:
			snprintf(path_and_file, BUFSIZE, ".%c%s%c%s", DIR_DELIMITER, "templates", DIR_DELIMITER, filename);
			break;
		case var_file_e:
			snprintf(path_and_file, BUFSIZE, ".%c%s%c%s", DIR_DELIMITER, "var", DIR_DELIMITER, filename);
			break;
		default:
			snprintf(path_and_file, BUFSIZE, "%s", filename);
	}
	
	xa_debug(3, "DEBUG: get_ntripcaster_file(): Looking for %s", path_and_file);

	if (access(path_and_file, flags) == 0)
		return path_and_file;

	switch (type) {
		case conf_file_e:
			snprintf(path_and_file, BUFSIZE, "..%c%s%c%s", DIR_DELIMITER, "conf", DIR_DELIMITER, filename);
			break;
		case log_file_e:
			snprintf(path_and_file, BUFSIZE, "..%c%s%c%s", DIR_DELIMITER, "logs", DIR_DELIMITER, filename);
			break;
		case template_file_e:
			snprintf(path_and_file, BUFSIZE, "..%c%s%c%s", DIR_DELIMITER, "templates", DIR_DELIMITER, filename);
			break;
		case var_file_e:
			snprintf(path_and_file, BUFSIZE, "..%c%s%c%s", DIR_DELIMITER, "var", DIR_DELIMITER, filename);
			break;
		default:
			snprintf(path_and_file, BUFSIZE, "%s", filename);
	}
	
	xa_debug(3, "DEBUG: get_ntripcaster_file(): Looking for %s", path_and_file);

	if (access(path_and_file, flags) == 0)
		return path_and_file;

	xa_debug (2, "DEBUG: get_ntripcaster_file(): Didn't find %s", filename);

	return NULL;
}

/* now in kilobytes instead of megabytes. ajd */
#define KILO (32*32)
void
stat_add_read (statistics_t *stat, int len)
{
	while (stat->read_bytes + len >= KILO)
	{
		stat->read_kilos++;
		len -= KILO;
	}

	stat->read_bytes += len;
}

void
stat_add_write (statistics_t *stat, int len)
{
	while (stat->write_bytes + len >= KILO)
	{
		stat->write_kilos++;
		len -= KILO;
	}

	stat->write_bytes += len;
}

char *
type_of_str (contype_t type, char *buf)
{
	if (type == admin_e)
		sprintf (buf, "admin");
	else if (type == client_e)
		sprintf (buf, "client");
	else if (type == source_e)
		sprintf (buf, "source");
	else
		sprintf (buf, "unknown");

	return buf;
}

/*
void
zero_song_info (songinfo_t *si)
{
	si->streamurl = NULL;
	si->streammsg = NULL;
	si->streamtitle = NULL;
	si->streamlength = -1;
	si->udpseqnr = 0;
}
*/

void
my_sleep (int microseconds)
{
#ifdef _WIN32
	Sleep (microseconds/1000); /* Does this really work? */
#else
# ifdef HAVE_NANOSLEEP
        struct timespec req, rem;
	long nanoseconds;

	req.tv_sec = 0;
	req.tv_nsec = 0;
	
	while (microseconds > 999999) {
		req.tv_sec++;
		microseconds -= 1000000;
	}

	nanoseconds = microseconds * 1000;
 
        while (nanoseconds > 999999999)
        {
                req.tv_sec++;
                nanoseconds -= 1000000000;
        }

        req.tv_nsec = nanoseconds;

/*	xa_debug (1, "DEBUG: Will sleep for %d seconds and %d nanoseconds", req.tv_sec, req.tv_nsec); */

        switch (nanosleep (&req, &rem)) {
		case EINTR:
			xa_debug (4, "WARNING: nanosleep() was interupted by nonblocked signal");
			break;
		case EINVAL:
			xa_debug (1, "WARNING: nanosleep() was passed invalid or negative sleep value %ld+%ld",
				  req.tv_sec, req.tv_nsec);
			break;
	}

# elif HAVE_SELECT
        struct timeval sleeper;
        sleeper.tv_sec = 0;
        sleeper.tv_usec = microseconds;
        select (1, NULL, NULL, NULL, &sleeper);
# else
        usleep (microseconds);
# endif
#endif
}

void
show_runtime_configuration ()
{
	xa_debug (1, "Runtime Configuration:");
#if defined(HAVE_NANOSLEEP)
	xa_debug (1, "Using nanosleep() as sleep method");
#elif defined(HAVE_SELECT)
	xa_debug (1, "Using select() as sleep method");
#else
#ifdef _WIN32
	xa_debug (1, "Using Sleep() as sleep method");
#else
	xa_debug (1, "Using usleep() as sleep method - THIS MAY BE UNSAFE");
#endif
#endif

#ifdef HAVE_SIGACTION
	xa_debug (1, "Using posix signal interface to block all signals in threads that don't want them");
#endif

	xa_debug (1, "Using %d chunks of %d bytes for client backlog", CHUNKLEN, SOURCE_READSIZE);

	switch (info.resolv_type)
	{
		case solaris_gethostbyname_r_e:
			xa_debug (1, "Using solaris own gethostbyname_r() and getaddrbyname_r(), which is good.");
			break;
		case linux_gethostbyname_r_e:
			xa_debug (1, "Using linux own gethostbyname_r() and getaddrbyname_r(), which is good.");
			break;
		case standard_gethostbyname_e:
			xa_debug (1, "Using standard gethostbyname() and getaddrbyname(), which might be dangerous cause it's not threadsafe!");
			break;
	}

#ifdef PTHREAD_THREADS_MAX
	xa_debug (1, "System can create max %d threads", PTHREAD_THREADS_MAX);
#endif
}

int
is_recoverable (int error)
{
#ifdef _WIN32
	if ((WSAGetLastError() == WSAEWOULDBLOCK) || (WSAGetLastError() == WSAEINTR) || (WSAGetLastError() == WSAEINPROGRESS)) 
		return 1;
#else
	if ((error == EAGAIN) || (error == EINTR) || (error == EINPROGRESS))
		return 1;
#endif

#ifdef SOLARIS
	if ((error == EWOULDBLOCK))
	  return 1;
#endif

#ifdef LINUX
	if (error == EIO) /* Works around a very very weird error with gdb and linux */
		return 1;
#endif

	return 0;
}

void
set_run_path (char **argv)
{
	char *pos;
	int i;

	if (!argv || !argv[0]) {
		fprintf (stderr, "WARNING: Weird NULL pointer in argv\n");
		return;
	}

	/* Where are we running from? */
	info.runpath = strdup (argv[0]);	
	running = SERVER_INITIALIZING;
	pos = strrchr (info.runpath, DIR_DELIMITER);
	if (pos) {
		*(pos + 1) = '\0';
		i = strlen(info.runpath) - 1;
		if ((i >= 3) && 
		    (info.runpath[i-1] == 'n' || info.runpath[i-1] == 'N') &&
		    (info.runpath[i-2] == 'i' || info.runpath[i-3] == 'I') &&
		    (info.runpath[i-3] == 'b' || info.runpath[i-4] == 'B')) {
			info.runpath[i-3] = '\0';
		}
	}
}

void
zero_audiocast (audiocast_t *au)
{
	au->name = NULL;
//	au->genre = NULL;
//	au->bitrate = -1;
//	au->url = NULL;
	au->mount = NULL;
//	au->description = NULL;
//	au->streammimetype = NULL;
//	au->contentid = NULL;
//	au->public = -1;
}

void
dispose_audiocast (audiocast_t *au)
{
	if (!au) return;
	nfree (au->name);
//	nfree (au->genre);
//	nfree (au->url);
	nfree (au->mount);
//	nfree (au->description);
//	nfree (au->streammimetype);
//	nfree (au->contentid);
}

int
is_valid_http_request (ntrip_request_t *req)
{
	if (!req->path[0]) return 0;
	return 1;
}

/* must have sourcetable_mutex. ajd */
/*
void
read_sourcetable() {
	int st;
	char *sourcetablefile;
	char szBuffer[BUFSIZE], element[BUFSIZE];
	sourcetable_entry_t *newste = NULL, *oldste = NULL, *oldste_net = NULL;
	
	info.sourcetable.length = 0;
	info.sourcetable.upd_length = 0;
	
	sourcetablefile = get_ntripcaster_file ("sourcetable.dat", conf_file_e, R_OK);
	st = open_for_reading(sourcetablefile);

	if (st > -1) {
 		while (fd_read_line (st, szBuffer, BUFSIZE)) {

			newste = (sourcetable_entry_t *)nmalloc (sizeof(sourcetable_entry_t));
			newste->line = nstrdup(szBuffer);
			
			if (splitc(element, szBuffer, ';') == NULL) {
				nfree(newste->line);
				nfree(newste);
				newste = NULL;
				continue;
			} else newste->type = nstrdup(element);
			
			if (splitc(element, szBuffer, ';') == NULL) {
				nfree(newste->type);
				nfree(newste->line);
				nfree(newste);
				newste = NULL;
				continue;
			} else {
				if (element[0] != '/') {
					char tmpmount[BUFSIZE];
					sprintf(tmpmount, "/%s", element);
					strncpy (element, tmpmount, BUFSIZE);
				}
				newste->mount = nstrdup(element);
			}

			if (splitnc(element, szBuffer, ';', 6) == NULL)
				newste->net = NULL;
			else
				newste->net = nstrdup(element);

			if (strncmp(newste->type, "STR", 3) == 0)
				newste->is_connected = 0;
			else {
				newste->is_connected = 1;
				info.sourcetable.upd_length += strlen(newste->line)+2;
			}

			oldste_net = avl_replace(info.sourcetable.net_tree, newste);
			oldste = avl_replace(info.sourcetable.tree, newste);

			if (oldste != NULL) {
				info.sourcetable.length -= (strlen(oldste->line)+2);
				if (oldste->is_connected == 1) info.sourcetable.upd_length -= (strlen(oldste->line)+2);

				nfree(oldste->type);
				nfree(oldste->mount);
				nfree(oldste->net);
				nfree(oldste->line);
				nfree(oldste);
				oldste = NULL;
			}

			info.sourcetable.length += strlen(newste->line)+2;
		}
		fd_close(st);
	} else write_log(LOG_DEFAULT, "WARNING: Could not open sourcetable.dat !");

	free(sourcetablefile);
}
*/

/*
void
sourcetable_add_connected_source(source_t *source)
{
	sourcetable_entry_t search, *ste = NULL;
	
	search.type = "STR";
	search.mount = source->audiocast.mount;
	
write_to_logfile(LOG_DEFAULT,"sdbg21");
	
	thread_mutex_lock(&info.sourcetable_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg22");

	ste = avl_find(info.sourcetable.tree, &search);
	
	if (ste != NULL) {
		ste->is_connected = 1;
		source->ste = ste;
		info.sourcetable.upd_length += strlen(ste->line)+2; // +2 because of missing CR and LF. ajd
	}

	thread_mutex_unlock(&info.sourcetable_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg23");

}
*/

/*
void
sourcetable_remove_connected_source(source_t *source)
{
	if (source->ste != NULL) {
	
write_to_logfile(LOG_DEFAULT,"sdbg31");
	
		thread_mutex_lock(&info.sourcetable_mutex);
		
write_to_logfile(LOG_DEFAULT,"sdbg32");	

		source->ste->is_connected = 0;
		info.sourcetable.upd_length -= strlen(source->ste->line)-2; // CR and LF. ajd
		source->ste = NULL;
		thread_mutex_unlock(&info.sourcetable_mutex);
		
write_to_logfile(LOG_DEFAULT,"sdbg33");

	}
}
*/


/*
void
rehash_sourcetable()
{
	avl_traverser trav2 = {0};
	sourcetable_entry_t *ste;
	sourcetable_entry_t search;
	connection_t *source;
	
write_to_logfile(LOG_DEFAULT,"sdbg41");
	
	thread_mutex_lock(&info.double_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg42");

	thread_mutex_lock(&info.sourcetable_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg43");	

	thread_mutex_lock(&info.source_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg44");
	
	free_sourcetable_tree();
	
	read_sourcetable();

// rebuild connection state. ajd
	search.type = "STR";
	ste = NULL;

	while ((source = avl_traverse (info.sources, &trav2))) {
		search.mount = source->food.source->audiocast.mount;
		ste = avl_find(info.sourcetable.tree, &search);
		if (ste != NULL) {
			ste->is_connected = 1;
			source->food.source->ste = ste;
			info.sourcetable.upd_length += strlen(ste->line)+2; // CR and LF. ajd
		} else source->food.source->ste = NULL;
		ste = NULL;
	}
	
	thread_mutex_unlock(&info.source_mutex);
	thread_mutex_unlock(&info.sourcetable_mutex);
	thread_mutex_unlock(&info.double_mutex);
	
write_to_logfile(LOG_DEFAULT,"sdbg45");
	
}
*/

/* must have sourcetable_mutex. ajd */
/*void
free_sourcetable_tree()
{
	avl_traverser trav = {0};
	sourcetable_entry_t *ste;

	while ((ste = avl_traverse (info.sourcetable.tree, &trav)))
	{
		nfree(ste->type);
		nfree(ste->mount);
		nfree(ste->net);
		nfree(ste->line);
		nfree(ste);	
	}
	
	avl_destroy(info.sourcetable.tree, NULL);
	avl_destroy(info.sourcetable.net_tree, NULL);
	
	info.sourcetable.tree = avl_create(compare_sourcetable_entrys, &info);
	info.sourcetable.net_tree = avl_create(compare_sourcetable_entrys_net, &info);	
}
*/

/* Update sourcetable.dat.upd with values from sourcetable.dat . ajd */
/*
void update_sourcetable() {
	FILE *st, *utdst; // input, output file. ajd
	char sourcetablefile[BUFSIZE];
	char szBuffer[2000], c[2], tmpszBuffer[2000], tmpbuf[BUFSIZE], mount[BUFSIZE];
	int nBytes = 1, nBufferBytes = 0;
	int success = 0;

//	write_log (LOG_DEFAULT, "Updating Sourcetable.");

	if (get_ntripcaster_file (info.sourcetablefile, conf_file_e, R_OK, sourcetablefile) == NULL) {
		write_log(LOG_DEFAULT, "WARNING: Could not find sourcetable file!");
		return;
	}

	utdst = fopen(info.sourcetablexxxfile,"w");
	if (utdst != NULL) {
	
		st = fopen(sourcetablefile,"r");
		if (st != NULL) {
			while (nBytes > 0) {
				nBytes = fread(c,sizeof(char),sizeof(char),st);
				while (((unsigned int)c[0] != 10) && (nBytes > 0)) { // 10 = LF (LineFeed, '\n`). ajd
					szBuffer[nBufferBytes] = c[0];
					nBufferBytes++;
					nBytes = fread(c,sizeof(char),sizeof(char),st);
				}
	
				szBuffer[nBufferBytes] = '\0';
	
	// search for mountpoint. if found, write line to "sourcetable.dat.upd". ajd
				if (nBufferBytes > 2) {
					strcpy(tmpszBuffer, szBuffer);
					splitc(tmpbuf, tmpszBuffer, ';');
	
					if (strncmp(tmpbuf, "STR", 3) == 0) {
						splitc(tmpbuf, tmpszBuffer, ';');
						if (tmpbuf[0] != '/')		// mountpoints in sourcetable without "/". ajd
							sprintf(mount, "/%s", tmpbuf);
						else
							strcpy(mount, tmpbuf);
						if ((find_source_with_mount(mount) != NULL) || (get_alias_with_mount(mount) != NULL))
							fprintf(utdst, "%s\n", szBuffer);
					} else fprintf(utdst, "%s\n", szBuffer);
				}
				nBufferBytes = 0;
			}
	
			success = 1;
			fclose(st);
		}
		fclose(utdst);
	}

	if (success == 1) rename(info.sourcetablexxxfile,info.sourcetableutdfile);
}
*/

/* count current number of connected clients. ajd */
/*
int
count_clients() {

	connection_t *clicon, *sourcecon;
	avl_traverser trav = {0}, sourcetrav = {0};
	int num = 0;

	thread_mutex_lock (&info.double_mutex);
	thread_mutex_lock (&info.source_mutex);

	while ((sourcecon = avl_traverse (info.sources, &sourcetrav)))
	{
		zero_trav (&trav);
		thread_mutex_lock (&sourcecon->food.source->mutex);

		while ((clicon = avl_traverse (sourcecon->food.source->clients, &trav))) num++;
	
		thread_mutex_unlock (&sourcecon->food.source->mutex);
	}

	thread_mutex_unlock (&info.source_mutex);
	thread_mutex_unlock (&info.double_mutex);

	return num;
}
*/

/*
char *
get_arguments_of_type(com_request_t *req, char *type) {

	int i = 0;

	while ((i < 10) && (req->typearg[i] != NULL)) {

		if (strncmp(req->typearg[i], type, 2) == 0) return strchr(req->typearg[i], ' ') + 1;
 		i++;
	}

	return NULL;
}

*/
/*
 * Lets the thread sleep a random amount of time (maximal max seconds). ajd
 */
void
sleep_random(int max) {

	my_sleep(((rand()%(max*1000))+1)*1000); // 'my_sleep' expects microseconds. ajd
}

long
read_starttime() {
	char pathandfile[BUFSIZE];
	char stringtime[BUFSIZE];
	int fd;
	long time;

	if (get_ntripcaster_file ("starttime", var_file_e, R_OK, pathandfile) == NULL) return -1;
	
	fd = open_for_reading(pathandfile);
	
	if (fd < 0) return -1;
	
	fd_read_line (fd, stringtime, BUFSIZE);
	
	fd_close(fd);
	
	time = atol(stringtime);
	
	if (time > 0) return time;
	
	return -1;
}

#ifdef DAILY_LOGFILES
void
start_new_day() {
//	char *acsfilename;
//	char csvfilename[BUFSIZE];

//	acsfilename = get_log_file(info.accessfilename);
//	snprintf (csvfilename, BUFSIZE, "%s.csv", acsfilename);
	
	get_short_date(info.date);

//	thread_mutex_lock(&info.logfile_mutex);

	open_log_files();

//	thread_mutex_unlock(&info.logfile_mutex);
	
//	rename(acsfilename, csvfilename);
	
//	xa_debug(1, "start_new_day():renamed accessfile %s to %s", acsfilename, csvfilename);
	
//	free (acsfilename);
}
#endif

int is_empty_request(ntrip_request_t *req) {
	if (req == NULL) return 1;
	if ((req->path[0] == '\0') || ((req->path[0] == '/') && (req->path[1] == '\0'))) return 1;

	return 0;
}

int get_file_size(FILE *ifp) {
	int fsize;

	fseek(ifp, 0, SEEK_END);
	fsize = (int)ftell(ifp);
	rewind(ifp);

	return fsize;
}

transfer_encoding_t get_transfer_encoding(const char *var) {
	if (strncasecmp(var, "chunked", 7) == 0)
		return chunked_e;
	else
		return not_chunked_e;
}

int is_big_endian() {
	int test = 1;
	return *((char *) &test) == 1;
}

list_t *list_create() {
	list_t *l = (list_t *)nmalloc(sizeof(list_t));

	l->size = 0;
	l->head = NULL;
	l->tail = NULL;

	return l;
}

void list_dispose_with_data(list_t *l, ntripcaster_function *free_func) {
	list_element_t *element = l->head, *next;

	while (element != NULL) {
		if (element->data != NULL) ((*(free_func))(element->data));
		next = element->next;
		nfree(element);
		element = next;
	}

	nfree(l);

	return;
}

void list_add(list_t *l, void *object) {
	list_element_t *new = (list_element_t *)nmalloc(sizeof(list_element_t));
	
	new->data = object;
	new->next = NULL;

	if (l->head == NULL) {
		l->head = new;
		l->tail = new;
	} else {
		l->tail->next = new;
		l->tail = new;
	}
	l->size++;
}

void *list_get(list_t *l, int i) {
	list_element_t *element;
	int c = 0;

	element = l->head;

	while ((element != NULL) && (c < i)) {
		element = element->next;
		c++;
	}

	if (element != NULL)
		return element->data;
	else
		return NULL;
}

void *list_next(list_enum_t *le) {
	list_element_t *ret;

	if (le->next == NULL) return NULL;

	ret = le->next;
	le->next = le->next->next;

	return ret->data;
}

void list_reset(list_enum_t *le) {
	le->next = le->list->head;
}

list_enum_t *list_get_enum(list_t *l) {
	list_enum_t *new = (list_enum_t *)nmalloc(sizeof(list_enum_t));
	
	new->list = l;
	new->next = l->head;
	
	return new;
}

string_buffer_t *string_buffer_create(int size) {
	string_buffer_t *sb = (string_buffer_t *)nmalloc(sizeof(string_buffer_t));

	sb->size = size+1;
	sb->pos = 0;
	sb->buf = nmalloc(size);
	sb->buf[0] = '\0';

	return sb;
}

void dispose_string_buffer(string_buffer_t *sb) {
	nfree(sb->buf);
	nfree(sb);
}

int write_string_to_buffer(string_buffer_t *sb, char *string) {
	char *spos = string;
	int old = sb->pos;

	if ((string != NULL) && (sb != NULL)) {
		while ((sb->pos < sb->size) && (*spos != '\0')) {
			sb->buf[sb->pos] = *spos;
			sb->pos++;
			spos++;
		}
		sb->buf[sb->pos] = '\0';
	}

	return (sb->pos-old);
}

int write_line_to_buffer(string_buffer_t *sb, char *string) {
	char *spos = string;
	int max = sb->size-2;
	int old = sb->pos;

	if ((string != NULL) && (sb != NULL)) {
		while ((sb->pos < max) && (*spos != '\0')) {
			sb->buf[sb->pos] = *spos;
			sb->pos++;
			spos++;
		}
		sb->buf[sb->pos++] = '\r';
		sb->buf[sb->pos++] = '\n';
		sb->buf[sb->pos] = '\0';
	}

	return (sb->pos-old);
}

/* The following two functions access "running" variable without mutex */
/* As the value is uncritical and atomic we assume this missing lock does no harm */
int is_server_running(void)
{
	return (running == SERVER_RUNNING);
}

void set_server_running(int state)
{
	running = state;
}
