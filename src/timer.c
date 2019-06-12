/* timer.c
 * - Thread for periodic events
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
#include <errno.h>

#ifndef __USE_BSD
#  define __USE_BSD
#endif

#ifndef __EXTENSIONS__
# define __EXTENSIONS__
#endif

#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <utime.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>

#include "avl.h"
#include "threads.h"
#include "ntripcastertypes.h"
#include "ntripcaster.h"
#include "ntrip.h"
#include "rtsp.h"
#include "utility.h"
#include "ntripcaster_string.h"
#include "threads.h"
#include "timer.h"
#include "logtime.h"
#include "avl_functions.h"
#include "log.h"
#include "sock.h"
#include "memory.h"
#include "client.h"
#include "commands.h"
#include "relay.h"
#include "source.h"

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

extern int errno;
extern server_info_t info;

void display_stats(statistics_t *stat);

/* Writes the one line status report to the log and the console if needed */
void status_write(server_info_t *infostruct)
{
	char timebuf[BUFSIZE];
	avl_traverser trav = {0};
	connection_t *con;
	char lt[100];
	long filetime;
	
	get_log_time(lt);
	
	filetime = read_starttime();
	if (filetime > 0)
		nntripcaster_time(get_time () - filetime, timebuf);
	else
		nntripcaster_time(get_time () - info.server_start_time, timebuf);

	while (is_server_running() && (con = avl_traverse(info.admins, &trav))) {
		if (con->food.admin->status && con->food.admin->alive) {
			if (con->host && ntripcaster_strcmp(con->host, "NtripCaster console") == 0) {
				printf("[%s] [Bandwidth: %fKB/s] [Sources: %ld] [Clients: %ld] [Admins: %ld] [Uptime: %s]\n-> ", lt,
				        info.bandwidth_usage, info.num_sources, info.num_clients, info.num_admins, 
					timebuf);
				fflush(stdout);
			} else {
				if (con->food.admin->scheme != tagged_scheme_e) {
					sock_write_line(con->sock, "[%s] [Bandwidth: %fKB/s] [Sources: %ld] [Clients: %ld] [Admins: %ld] [Uptime: %s]",
					   lt, info.bandwidth_usage, info.num_sources, info.num_clients, info.num_admins, 
					   timebuf);
				} else {
					sock_write_line(con->sock, "M%d [%s] [Bandwidth: %fKB/s] [Sources: %ld] [Clients: %ld] [Admins: %ld] [Uptime: %s]",
					   ADMIN_SHOW_STATUS, lt, info.bandwidth_usage, info.num_sources, info.num_clients, info.num_admins, 
					   timebuf);
				}

				sock_write(con->sock, "-> ");
			}
		}
	}

	write_log(LOG_USAGE, "[%s] Bandwidth:%fKB/s Sources:%ld Clients:%ld Admins:%ld", lt, info.bandwidth_usage, info.num_sources, info.num_clients, info.num_admins);

	//update_sourcetable();

}

/* Starts up the calendar thread.  the calendar thread is responsible
 * for directory server updates, cron jobs and such 
 */
void *startup_timer_thread(void *arg)
{
	time_t justone = 0, trottime = 0;
	statistics_t trotstat;
	mythread_t *mt;

	thread_init();

	mt = thread_get_mythread();

	while (thread_alive (mt)) {
		time_t stime = get_time();

//		timer_update_stats_files (stime); // not needed. ajd

//		timer_handle_directory_servers (stime); // not needed. ajd

		timer_handle_status_lines (stime);

		timer_handle_transfer_statistics (stime, &trottime, &justone, &trotstat);

//		timer_kick_abandoned_relays (stime);

#ifdef CHANGE5
#ifdef DAILY_LOGFILES
		timer_check_date(); // start_new_day in handle_transfer_statistics? ajd
#endif
#endif
		
		if (mt->ping == 1) mt->ping = 0;

		my_sleep(400000);
	}
	
	/* We don't know if we even got here, cause a thread_cancel() might have
	   killed us, so closing files and directories here is pointless */
	thread_exit(7);
	return NULL;
}

/*
void
timer_update_stats_files (time_t stime)
{
	if ((info.statstime) > 0) {
		if ((stime - info.statslasttime) >= info.statstime) {
			info.statslasttime = stime;
			stats_write(&info);
			stats_write_html(&info);
		}
	}
}
*/

/* // nod needed. ajd
void
timer_handle_directory_servers (time_t stime)
{
	avl_traverser trav = {0};
	directory_server_t *ds;
	connection_t *defcon = get_default_mount();
	
	if ((stime - info.directorylasttime) >= info.touch_freq * 60) {
		// First xa servers, then icy servers.
		// Simply because it's ok, and needed to double lock
		// the xa stuff, because we're traversing multiple
		// sources and stuff. And with icy, we can't double lock
		// at all, because friggin yp.shoutcast.com sux ass
		zero_trav(&trav);
		
		thread_mutex_lock(&info.double_mutex);
		thread_mutex_lock(&info.directory_mutex);

		while ((ds = avl_traverse(info.d_servers, &trav))) {
			if (ds->type == icy_e)
				continue;
	
			if ((ds->id < 0) && (ds->counter > 0) 
			    && ((stime - ds->touchtime) < (info.touch_freq * ds->counter * 60))) {
				xa_debug(2, "DEBUG: Directory server [%s] still has %d seconds to go", ds->host, 
					 (stime - ds->touchtime) - (info.touch_freq * ds->counter * 60));
				continue;
			}
			
			directory_touch_xa (ds);
			ds->touchtime = stime;
		}

		thread_mutex_unlock(&info.directory_mutex);
		thread_mutex_unlock(&info.double_mutex);

		thread_mutex_lock (&info.directory_mutex);

		while ((ds = avl_traverse(info.d_servers, &trav))) {
			if (ds->type != icy_e) continue;
	
			if ((ds->id < 0) && (ds->counter > 0) 
			    && ((stime - ds->touchtime) < (info.touch_freq * ds->counter * 60))) {
				xa_debug(2, "DEBUG: Directory server [%s] still has %d seconds to go", ds->host, 
					 (stime - ds->touchtime) - (info.touch_freq * ds->counter * 60));
				continue;
			}
			
			if (ds->id == -1) {
				if (defcon != NULL) {
					directory_add(ds, defcon);
					directory_touch(ds, defcon);
				}
			} else {
				directory_touch(ds, defcon);
			}
			ds->touchtime = stime;
		}

		thread_mutex_unlock (&info.directory_mutex);

		info.directorylasttime = stime;
	} else if (defcon == NULL) {
		thread_mutex_lock(&info.directory_mutex);
		while ((ds = avl_traverse(info.d_servers, &trav))) {
			if (ds->type != icy_e) continue;
			if (ds->id != -1) directory_remove(ds);
		}
		thread_mutex_unlock(&info.directory_mutex);
	}
}
*/

void
timer_handle_status_lines (time_t stime)
{
	if ((stime - info.statuslasttime) >= info.statustime) {
		info.statuslasttime = stime;
		status_write(&info);
	}
	
}

void
timer_handle_transfer_statistics (time_t stime, time_t *trottime, time_t *justone, statistics_t *trotstat)
{
	/* We keep the running statistics on a per hour basis.
	   Every hour the daily statistics get updated, and
	   we start over. Every day, the total statistics get
	   updated, and we start over for the day */
	if (get_time() != *justone) {
		*justone = get_time();
		
		/* Daily */
		if ((stime % 86400) == 0) {
			statistics_t stat, hourlystats;
			
//			start_new_day();
			
			zero_stats(&stat);

			get_hourly_stats(&hourlystats);
			zero_stats(&info.hourly_stats);
			update_daily_statistics(&hourlystats);
			
			get_daily_stats(&stat);
			zero_stats(&info.daily_stats);
			update_total_statistics(&stat);
			write_daily_stats(&stat);
		} else if ((stime % 3600) == 0) {  /* hourly */
			statistics_t stat;
			
			zero_stats(&stat);
			
			get_hourly_stats(&stat);
			zero_stats(&info.hourly_stats);
			update_daily_statistics(&stat);
			write_hourly_stats(&stat);
		} 
		
		if ((stime % 60) == 0) { /* Every 60 seconds */
			time_t delta;
			statistics_t stat;
			unsigned int total_bytes;

/* KB_per_sec was MB_per_sec. ajd */
			double KB_per_sec = 0;
			
			zero_stats(&stat);
			
			get_running_stats(&stat);
			
			if (*trottime == 0) {
				*trottime = get_time();
				get_running_stats(trotstat);
			} else {
				total_bytes = (stat.read_kilos - trotstat->read_kilos) + (stat.write_kilos - trotstat->write_kilos);
				delta = get_time() - *trottime; /* Should be about 60 unless weird stuff is going on */
				if (delta <= 0) {
					write_log(LOG_DEFAULT, 
						"ERROR: Losing track of time.. is it xmas already? [%d - %d == %d <= 0]", 
						get_time (), *trottime, delta);
				} else {
					KB_per_sec = (double)total_bytes / (double)delta;
					
					
					/* This is just me being paranoid, sometimes this value gets all fucked up for a while
					   and will make the server refuse connects. - Eel*/
					if (KB_per_sec < 40000000) { // 40000000 vorher 40000. ajd
						info.bandwidth_usage = KB_per_sec;
						if (!info.throttle_on && (info.throttle > 0.0) && (KB_per_sec > info.throttle)) {
							write_log(LOG_DEFAULT, "Throttling bandwidth: [Usage %f, specified throttle value: %f]",
								  KB_per_sec, info.throttle);
							info.throttle_on = 1;
						} else if (info.throttle_on && (KB_per_sec < info.throttle)) {
							write_log(LOG_DEFAULT, "Bandwidth [%f] back below limit [%f], allowing access", KB_per_sec,
								  info.throttle);
							info.throttle_on = 0;
						}
					}
				}
				
				get_running_stats(trotstat);
				*trottime = get_time();
			}
		}
	}
}

void
timer_kick_abandoned_relays (time_t stime)
{
	if ((stime % 100 == 0) && info.kick_relays) {
		avl_traverser trav = {0};
		connection_t *sourcecon;
		
		thread_mutex_lock(&info.source_mutex);
		while ((sourcecon = avl_traverse(info.sources, &trav))) {
			if (sourcecon->food.source->type == pulling_source_e && 
			    sourcecon->food.source->num_clients <= 0 && 
			    sourcecon->food.source->connected == SOURCE_CONNECTED 
			    && (get_time () - sourcecon->connect_time > info.kick_relays)) {

				kick_connection(sourcecon, "Closing relay (saving bandwidth)");
			}
		}
		thread_mutex_unlock(&info.source_mutex);
	}
}

void get_hourly_stats(statistics_t *stat)
{
	internal_lock_mutex (&info.misc_mutex);
	stat->read_bytes = info.hourly_stats.read_bytes;
	stat->write_bytes = info.hourly_stats.write_bytes;
	internal_unlock_mutex (&info.misc_mutex);

	stat->read_kilos = info.hourly_stats.read_kilos;
	stat->write_kilos = info.hourly_stats.write_kilos;
	
	stat->client_connections = info.hourly_stats.client_connections;
	stat->source_connections = info.hourly_stats.source_connections;
	stat->client_connect_time = info.hourly_stats.client_connect_time;
	stat->source_connect_time = info.hourly_stats.source_connect_time;
}

void write_hourly_stats(statistics_t *stat)
{
	char cct[BUFSIZE], sct[BUFSIZE];
	char timebuf[BUFSIZE];
	statistics_t running;

	get_current_stats(&running);
	add_stats(stat, &running, 0);

	strncpy(cct, connect_average (stat->client_connect_time, stat->client_connections + info.num_clients, timebuf), BUFSIZE);
	strncpy(sct, connect_average (stat->source_connect_time, stat->source_connections + info.num_sources, timebuf), BUFSIZE);
		 
	write_log(LOG_USAGE, "Hourly statistics: [Client connects: %lu] [Source connects: %lu] [Bytes read: %lu] [Bytes written: %lu]",
		   stat->client_connections, stat->source_connections, stat->read_bytes, stat->write_bytes);
	write_log(LOG_USAGE, "Hourly averages: [Client transfer: %lu bytes] [Source transfer: %lu] [Client connect time: %s] [Source connect time: %s]",
		   transfer_average (stat->write_bytes, stat->client_connections), transfer_average (stat->read_bytes, stat->source_connections),
		   cct, sct);
}

void update_daily_statistics(statistics_t *stat)
{
	thread_mutex_lock(&info.misc_mutex);
	info.daily_stats.read_bytes += (stat->read_bytes / 1000);
	info.daily_stats.write_bytes += (stat->write_bytes / 1000);
	info.daily_stats.client_connections += stat->client_connections;
	info.daily_stats.source_connections += stat->source_connections;
	info.daily_stats.client_connect_time += stat->client_connect_time;
	info.daily_stats.source_connect_time += stat->source_connect_time;
	thread_mutex_unlock(&info.misc_mutex);
}

void get_daily_stats (statistics_t *stat)
{
	thread_mutex_lock(&info.misc_mutex);
	stat->read_bytes = info.daily_stats.read_bytes;
	stat->write_bytes = info.daily_stats.write_bytes;
	stat->client_connections = info.daily_stats.client_connections;
	stat->source_connections = info.daily_stats.source_connections;
	stat->client_connect_time = info.daily_stats.client_connect_time;
	stat->source_connect_time = info.daily_stats.source_connect_time;
	thread_mutex_unlock(&info.misc_mutex);
}

void update_total_statistics(statistics_t *stat)
{
	thread_mutex_lock(&info.misc_mutex);
	info.total_stats.read_bytes += (stat->read_bytes / 1000);
	info.total_stats.read_kilos += (stat->read_bytes);

	info.total_stats.write_bytes += (stat->write_bytes / 1000);
	info.total_stats.write_kilos += (stat->write_bytes);

	info.total_stats.client_connections += stat->client_connections;
	info.total_stats.source_connections += stat->source_connections;
	info.total_stats.client_connect_time += stat->client_connect_time;
	info.total_stats.source_connect_time += stat->source_connect_time;
	thread_mutex_unlock(&info.misc_mutex);
}

void write_daily_stats(statistics_t *stat)
{
	char cct[BUFSIZE], sct[BUFSIZE];
	statistics_t running;
	char timebuf[BUFSIZE];

	get_current_stats(&running);
	add_stats(stat, &running, 0);

	strncpy(cct, connect_average (stat->client_connect_time, stat->client_connections + info.num_clients, timebuf), BUFSIZE);
	strncpy(sct, connect_average (stat->source_connect_time, stat->source_connections + info.num_sources, timebuf), BUFSIZE);
	
	write_log(LOG_USAGE, "Daily statistics: [Client connects: %lu] [Source connects: %lu] [Kbytes read: %lu] [Kbytes written: %lu]",
		   stat->client_connections, stat->source_connections, stat->read_bytes, stat->write_bytes);
	write_log(LOG_USAGE, "Daily averages: [Client transfer: %lu Kbytes] [Source transfer: %lu Kbytes] [Client connect time: %s] [Source connect time: %s]",
		   transfer_average (stat->write_bytes, stat->client_connections), transfer_average (stat->read_bytes, stat->source_connections),
		   cct, sct);
}
		
void get_current_stats(statistics_t *stat)
{
	get_current_stats_proc (stat, 1);
}

void get_current_stats_proc (statistics_t *stat, int lock)
{
	time_t ec = 0, cc = 0;
	
	zero_stats(stat);
	
	/* Lock the double mutex whenever you're about to lock twice */
	if (lock) thread_mutex_lock(&info.double_mutex);
	
	thread_mutex_lock(&info.source_mutex);
	ec = (time_t)tree_time(info.sources);
	thread_mutex_unlock(&info.source_mutex);
	
	thread_mutex_lock(&info.client_mutex);
	cc = (time_t)tree_time(info.clients);
	thread_mutex_unlock(&info.client_mutex);
	
	if (lock) thread_mutex_unlock(&info.double_mutex);

	stat->client_connect_time = cc;
	stat->source_connect_time = ec;
}

void get_running_stats(statistics_t *stat)
{
	get_running_stats_proc (stat, 1);
}

void get_running_stats_nl (statistics_t *stat)
{
	get_running_stats_proc (stat, 0);
}

void get_running_stats_proc (statistics_t *stat, int lock)
{
	statistics_t bufstat;

	/* in megabytes. ajd */
	stat->read_bytes = info.total_stats.read_bytes;
	stat->write_bytes = info.total_stats.write_bytes;
  //stat->read_megs = info.total_stats.read_megs;
	//stat->write_megs = info.total_stats.write_megs;

  /*in kilobytes. ajd */
	stat->read_kilos = info.total_stats.read_kilos;
	stat->write_kilos = info.total_stats.write_kilos;

	stat->client_connections = info.total_stats.client_connections;
	stat->source_connections = info.total_stats.source_connections;
	stat->client_connect_time = info.total_stats.client_connect_time;
	stat->source_connect_time = info.total_stats.source_connect_time;
	
        /* These in bytes */
	get_current_stats_proc (&bufstat, lock);
	add_stats(stat, &bufstat, 0);

	/* These in bytes */
	get_hourly_stats(&bufstat);
	add_stats(stat, &bufstat, 0);
	
	/* These in kilobytes */
	get_daily_stats(&bufstat);
	add_stats(stat, &bufstat, 1000);
}

void zero_stats(statistics_t *stat)
{
	if (!stat) {
		write_log (LOG_DEFAULT, "WARNING: zero_stats() called with NULL stat pointer");
		return;
	}

	stat->read_bytes = 0;
	stat->read_kilos = 0;
	//stat->read_megs = 0;

	stat->write_bytes = 0;
	stat->write_kilos = 0;
	//stat->write_megs = 0;

	stat->client_connections = 0;
	stat->source_connections = 0;
	stat->client_connect_time = 0;
	stat->source_connect_time = 0;
}

void add_stats(statistics_t *target, statistics_t *source, unsigned long int factor)
{
	double div;

	if (factor == 0)
		div = 1000000.0;
	else 
		div = (1000000.0 / (double)factor);
	
	target->read_bytes += (unsigned long)(source->read_bytes / div);
	target->read_kilos += (unsigned long)(source->read_bytes / (div / 1000));

	target->write_bytes += (unsigned long)(source->write_bytes / div);
	target->write_kilos += (unsigned long)(source->write_bytes / (div / 1000));

	target->client_connections += source->client_connections;
	target->client_connect_time += source->client_connect_time;
	target->source_connections += source->source_connections;
	target->source_connect_time += source->source_connect_time;
}
	
void display_stats(statistics_t *stat)
{
	xa_debug(1, "DEBUG: rb: %lu wb: %lu", stat->read_bytes, stat->write_bytes);
}

/*
void *startup_udp_info_thread(void *arg)
{
	SOCKET sends;
	avl_traverser trav = {0}, sourcetrav = {0};
	connection_t *clicon, *sourcecon;
	struct sockaddr_in serv, *recv_addr;
	socklen_t sinlen, outlen;
	char buf[BUFSIZE];
	mythread_t *mt;

	thread_init ();

	mt = thread_get_mythread();
	
	outlen = sinlen = sizeof(serv);
	
	recv_addr = (struct sockaddr_in *)nmalloc(sizeof (struct sockaddr_in));
	
	memset(&serv, 0, sinlen);
	memset(recv_addr, 0, sinlen);

	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(info.port[0]);

	if ((sends = sock_create_udp_socket()) < 0) {
		write_log(LOG_DEFAULT, "ERROR: Cannot create a udp socket for sending metainfo, shutting down udp traffic");
		thread_exit(0);
	}

	if (bind(sends, (struct sockaddr *)&serv, sinlen) < 0) {
		write_log(LOG_DEFAULT, "ERROR: Bind to udp interface failed, shutting down udp traffic");
		thread_exit(0);
	}

	sock_set_blocking(sends, SOCK_BLOCKNOT);
	
	while (thread_alive (mt)) {
		time_t stime = get_time();
	
		int n = recvfrom(sends, buf, BUFSIZE - 1, 0, (struct sockaddr *)recv_addr, &outlen);

		if (mt->ping == 1)
			mt->ping = 0;

		if (n > 0) {
			buf[n] = '\0';
			if (strstr (buf, "PING")) {
				sendto(sends, buf, n, MSG_DONTWAIT, (struct sockaddr *)recv_addr, outlen);
				xa_debug(1, "DEBUG: echoed back [%s]", buf);
			} else if (strstr (buf, "x-audiocast-ack:")) {
				char *seqnr = strchr(buf, ':');
				if (seqnr) {
					connection_t *updatecon = find_con_with_host(recv_addr);
					
					if (updatecon && updatecon->type == client_e && updatecon->food.client) {
						updatecon->food.client->udpseqnr = atol(seqnr + 1);
						xa_debug(3, "DEBUG: Received ack from %s", con_host(updatecon));
					} else {	
						xa_debug(1, "Warning: udp ack from unknown client connection");
					}
				}
			} else if (strstr(buf, "x-audiocast-udpport")) {
				char hbuf[BUFSIZE], *hostptr;
				char *portptr = strchr(buf, ':');
				connection_t *updatecon;
				if (portptr) {
					xa_debug(2, "DEBUG: udp port change from %d to %d", atoi (portptr + 1), recv_addr->sin_port);

				        // Change the outgoing port for this connection to what he's sending from
					hostptr = makeasciihost(&recv_addr->sin_addr, hbuf);
					updatecon = find_con_with_host_and_udpport(hostptr, atoi (portptr + 1));
					if (!updatecon) {
						xa_debug(1, "DEBUG: Invalid port change from [%s]", hostptr);
					} else {
						updatecon->sin->sin_port = recv_addr->sin_port;
						if (updatecon->type == client_e && updatecon->food.client && (updatecon->food.client->udpseqnr > 0))
							updatecon->food.client->udpseqnr--; // Force update
					}
				}
			}
		}
		
		if ((stime - info.udpupdatelasttime) >= info.udpupdatetime) {
			// First go through the sources and see if the title changes
			thread_mutex_lock(&info.double_mutex);
			thread_mutex_lock(&info.source_mutex);
			zero_trav (&sourcetrav);
			while ((sourcecon = avl_traverse(info.sources, &sourcetrav))) {
				time_t t = get_time ();
				if (sourcecon && sourcecon->food.source && sourcecon->food.source->connected == SOURCE_CONNECTED) {
					zero_trav(&trav);
					thread_mutex_lock(&sourcecon->food.source->mutex);
					while ((clicon = avl_traverse(sourcecon->food.source->clients, &trav))) 
					{
						if (client_wants_udp_info (clicon) && (t - clicon->connect_time > 5) && 
						    (clicon->food.client->udpseqnr < sourcecon->food.source->info.udpseqnr))
							udp_update_metainfo (sends, sourcecon, clicon);
					}
					thread_mutex_unlock(&sourcecon->food.source->mutex);				
				}
			}
			thread_mutex_unlock(&info.source_mutex);
			thread_mutex_unlock(&info.double_mutex);
		}
		
		my_sleep(500000);
	}
	
	thread_exit(2);
	return NULL;
}
*/


void *startup_relay_connector_thread(void *arg)
{
	mythread_t *mt;

	if (!info.relays) {
		write_log (LOG_DEFAULT, "WARNING: startup_relay_connector_thread(): info.relays is NULL, weeird!");
	}

	thread_init();

	mt = (mythread_t *) thread_get_mythread ();

	while (thread_alive (mt))
	{
		relay_connect_all_relays ();
		my_sleep ((info.relay_reconnect_time / 2) * 1000000);

		if (mt->ping == 1)
			mt->ping = 0;
	}
	
	thread_exit (2);
	return NULL;
}

void *startup_heartbeat_thread(void *arg)
{
	thread_init();

#ifdef NTRIP_NUMBER
	xa_debug(1, "DEBUG: Server is optimized, can't use heartbeat thread");
	thread_exit(0);
#endif

  /* This might do something one day.. 
     Problem is adding a time variable to every mutex and a call to time(NULL)
     for every lock/unlock, would create a big overhead.
     An alternative would be to check the thread_id on every lock 3 times every
     MAX_MUTEX_LOCKTIME seconds, and if the thread_id is the same all thread
     checks, then it is probably safe to presume it is deadlocked */

  	thread_exit(0);
	return 0;
  /*
    while (running)
    {
    t = get_time ();
    if (t % (MAX_MUTEX_LOCKTIME / 3) == 0)
    {
  */
}

void *startup_watchdog_thread(void *arg)
{
	mythread_t *mt;
	char watchdog[BUFSIZE];

	thread_init();

	mt = thread_get_mythread();

	get_ntripcaster_file(info.watchfile, var_file_e, R_OK, watchdog);

	while (thread_alive (mt)) {
		if (info.main_thread->ping == 0) utime(watchdog, NULL);
		info.main_thread->ping = 1;
		my_sleep(WATCHDOG_TIME * 1000000);
	}

	thread_exit(0);
	return 0;
}

void add_fmt_string(char *buf, const char *fmt, char *val)
{
	char buf2[256];
	if (!buf || !fmt || !val)
		return;

	if (ntripcaster_strlen (val) > 230)
		val[230] = '\0';

	snprintf(buf2, 256, fmt, val);
	strncat(buf, buf2, 1023 - ntripcaster_strlen (buf));
}

void add_fmt_int(char *buf, const char *fmt, long int val)
{
	char buf2[256];
	if (!buf || !fmt)
		return;
	snprintf(buf2, 256, fmt, val);
	strncat(buf, buf2, 1023 - ntripcaster_strlen (buf));
}

/*
int 
udp_update_metainfo(SOCKET s, connection_t *sourcecon, connection_t *clicon)
{
	char buf[1024]; // Make it fit into the mtu.. that should be safe?

	xa_debug (1, "Updating metadata for host %s", con_host (clicon));

	if (!sourcecon || !clicon) {
		xa_debug(1, "WARNING: udp_update_metainfo: called with NULL pointers");
		return 0;
	} else if (!sock_valid (s)) {
		xa_debug(1, "WARNING: udp_update_metainfo(): called with invalid socket");
		return 0;
	}

	buf[0] = '\0';

	add_fmt_int(buf, "x-audiocast-udpseqnr: %ld\r\n", sourcecon->food.source->info.udpseqnr);
//	add_fmt_string(buf, "x-audiocast-streamtitle: %s\r\n", sourcecon->food.source->info.streamtitle);
//	add_fmt_string(buf, "x-audiocast-streamurl: %s\r\n", sourcecon->food.source->info.streamurl);
//	add_fmt_string(buf, "x-audiocast-streammsg: %s\r\n", sourcecon->food.source->info.streammsg);
//	add_fmt_int(buf, "x-audiocast-streamlength: %ld\r\n", sourcecon->food.source->info.streamlength);

	if (sendto(s, buf, ntripcaster_strlen(buf), MSG_DONTWAIT, (struct sockaddr *)clicon->sin, clicon->sinlen) == -1) {
		xa_debug(1, "WARNING: sendto(%s) failed with [%d]", con_host(clicon), errno);
		return 0;
	}

	return 1;
}
*/

void
timer_check_date() {

	char today[50];

	get_short_date(today);

	if (strncmp(info.date, today, 6) != 0) {
		start_new_day();
	}
}
