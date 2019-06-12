/* log.c
 * - Logging Functions
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
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <io.h>
#define write _write
#define read _read
#define close _close
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <fcntl.h>

#include "avl.h"
#include "threads.h"
#include "ntripcastertypes.h"
#include "ntripcaster.h"
#include "ntrip.h"
#include "logtime.h"
#include "log.h"
#include "admin.h"
#include "sock.h"
#include "utility.h"
#include "ntripcaster_string.h"
#include "avl_functions.h"
#include "timer.h"
#include "memory.h"
#include "main.h"
#include "http.h"
#include "vars.h"
#include "connection.h"
#include "authenticate/basic.h"
#include "authenticate/user.h"


extern int errno, running;
extern server_info_t info;

/* logs client accesses. ajd */
void
write_clf (connection_t *clicon, source_t *source) {
	char *mount;
		
	char time[100];
	char date[100];
//	const char *refptr;
	const char *uaptr;
	ntripcaster_user_t *user;
	
	get_regular_time(time);
	get_regular_date(date);

	if (!clicon) {
		write_log(LOG_DEFAULT, "WARNING: Could not write access file (client connection NULL)");
		return;
	}

	if (clicon->ghost == 1) return; // no logging. ajd
	
	if (info.accessfile == -1) {
		write_log(LOG_DEFAULT, "WARNING: Could not write access file (invalid file descriptor)");
		return;
	}

	user = con_get_user (clicon);

	mount = (source && source->audiocast.mount) ? source->audiocast.mount+1 : "n/a";

//	refptr = get_con_variable (clicon, "Referer");
	uaptr = get_user_agent (clicon);
	
//#ifdef DAILY_LOGFILES
//	thread_mutex_lock(&info.logfile_mutex);
//#endif
	if (info.accessfile > -1) {
		thread_mutex_lock(&info.logfile_mutex);
		fd_write_line (info.accessfile, "%s,%s,%s,%s,%s,%s,%d,%lu", date, time, (user != NULL)?nullcheck_string(user->name):"(null)", clicon->host ? clicon->host : "?", mount, uaptr ? uaptr : "?", get_time () - clicon->connect_time, clicon->food.client->write_bytes);
		thread_mutex_unlock(&info.logfile_mutex);
	}

//#ifdef DAILY_LOGFILES
//	thread_mutex_unlock(&info.logfile_mutex);
//#endif
	
/*	
	fd_write_line (info.accessfile, "%s %s %s [%s] %s %lu \"%s\" %d", con_host (clicon), nullcheck_string (clicon->host), user.name ? user.name : "-", timeptr = get_clf_log_time (),
		       mount, clicon->food.client->write_bytes, uaptr ? uaptr : "-", get_time () - clicon->connect_time);
*/
	if (user != NULL) {
		nfree(user->name);
		nfree(user->pass);
		nfree(user);
	}
}

int
get_log_fd (int whichlog)
{
// added. ajd
	if (whichlog == LOG_DEFAULT)
//		if (info.logfile != -1)
			return info.logfile;

	if (whichlog == LOG_USAGE)
//		if (info.usagefile != -1)
			return info.usagefile;
	if (whichlog == LOG_ACCESS)
//		if (info.accessfile != -1)
			return info.accessfile;
	
	return info.logfile;
}


void 
write_log (int whichlog, char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	char logtime[100];
	avl_traverser trav = {0};
	connection_t *con;
	admin_t *admin;
	mythread_t *mt = thread_check_created ();
	int fd = get_log_fd (whichlog);

	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
  
	if (!mt) fprintf (stderr, "WARNING: No mt while outputting [%s]", buf);

	get_log_time(logtime);

	if (strstr (buf, "%s") != NULL) {
		fprintf (stderr, "WARNING, write_log () called with '%%s' formatted string [%s]!", buf);
		return;
	}

	if (mt && (fd > -1)) {
		int retval;
		thread_mutex_lock(&info.logfile_mutex);
		retval = fd_write (fd, "[%s] [%d:%s] %s\n", logtime, mt->id, nullcheck_string (mt->name), buf);
		thread_mutex_unlock(&info.logfile_mutex);
		if (retval == 0)
			fprintf (stderr, "WARNING: No bytes written to logfile !!!");
		else if (retval == -1)
			fprintf (stderr, "WARNING: Writing to logfile failed !!!");
	}

	if (whichlog != LOG_DEFAULT)
	{
		va_end (ap);
		return;
	}

	if (info.console_mode == CONSOLE_LOG) {
		printf("\r[%s] %s\n", logtime, buf);
		fflush(stdout);
	}

	
/* here and in functions below might be a problem
 (not mutex protected access to admin tree). ajd */

	if (is_server_running()) {
//		thread_mutex_lock(&info.admin_mutex); // added locking. ajd
		while ((con = avl_traverse(info.admins, &trav)) != NULL) {
			admin = (admin_t *)con->food.admin;
			if (con->type != admin_e) {
				printf("ERROR IN TYPE in id %ld\n", con->id);
				continue;
			}
			if (admin->tailing && admin->alive) {
			  if (ntripcaster_strcmp (con->host, "NtripCaster console") == 0)
			    {
		  	    printf ("[%s] %s\n-> ", logtime, buf);
		    	  fflush (stdout);
		   	 }
			  else
			    {
			      sock_write_line (con->sock, "[%s] %s", logtime, buf);
			      sock_write (con->sock, "->");
		  	  }
			}
		}
//		thread_mutex_unlock(&info.admin_mutex); // added locking. ajd
	} else if (info.console_mode != CONSOLE_LOG) {
		fprintf (stderr, "[%s] %s\n", logtime, buf);
	}
	
	va_end (ap);
}

void 
log_no_thread (int whichlog, char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	char logtime[100];
	avl_traverser trav = {0};
	connection_t *con;
	admin_t *admin;
	int fd = get_log_fd (whichlog);


	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
  
	get_log_time(logtime);

	if (strstr (buf, "%s") != NULL) {
		fprintf (stderr, "WARNING, write_log () called with '%%s' formatted string [%s]!", buf);
		return;
	}

	if (fd > -1) {
		thread_mutex_lock(&info.logfile_mutex);
		fd_write (fd, "[%s] %s\n", logtime, buf);
		thread_mutex_unlock(&info.logfile_mutex);
	}

	if (whichlog != LOG_DEFAULT)
	{
		va_end (ap);
		return;
	}

	if (info.console_mode == CONSOLE_LOG) {
		printf("\r[%s] %s\n", logtime, buf);
		fflush(stdout);
	}

	if (is_server_running()) {
		while ((con = avl_traverse(info.admins, &trav)) != NULL) {
			admin = (admin_t *)con->food.admin;
			if (con->type != admin_e) {
				printf("ERROR IN TYPE in id %ld\n", con->id);
				continue;
			}
			if (admin->tailing && admin->alive) {
			  if (ntripcaster_strcmp (con->host, "NtripCaster console") == 0)
			    {
			      printf ("[%s] %s\n-> ", logtime, buf);
		  	    fflush (stdout);
		    	}
			  else
			    {
			      sock_write_line (con->sock, "[%s] %s", logtime, buf);
			      sock_write (con->sock, "->");
		  	  }
			}
		}
	} else if (info.console_mode != CONSOLE_LOG) {
		fprintf (stderr, "[%s] %s\n", logtime, buf);
	}

	va_end (ap);

}

void 
write_log_not_me (int whichlog, connection_t *nothim, char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	char logtime[100];
	avl_traverser trav = {0};
	connection_t *con;
	admin_t *admin;

	int fd = get_log_fd (whichlog);

	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
  
	get_log_time(logtime);

	if (strstr (buf, "%s") != NULL) {
		fprintf (stderr, "WARNING, xa_debug() called with '%%s' formatted string [%s]!", buf);
		return;
	}

	if (fd != -1) {
		thread_mutex_lock(&info.logfile_mutex);
		fd_write (fd, "[%s] %s\n", logtime, buf);
		thread_mutex_unlock(&info.logfile_mutex);
	}

	if (whichlog != LOG_DEFAULT)
	{
		va_end (ap);
		return;
	}

	if (info.console_mode == CONSOLE_LOG) {
		printf("\r[%s] %s\n", logtime, buf);
		fflush(stdout);
	}

	if (is_server_running()) {
		while ((con = avl_traverse(info.admins, &trav)) != NULL) {
			admin = (admin_t *)con->food.admin;
			if (con->type != admin_e) {
				printf("ERROR IN TYPE in id %ld\n", con->id);
				continue;
			}
			if (admin->tailing && admin->alive && con->id != nothim->id) {
				if (ntripcaster_strcmp (con->host, "NtripCaster console") == 0)
				{
					printf ("[%s] %s\n-> ", logtime, buf);
					fflush (stdout);
				}
				else
				{
					sock_write_line (con->sock, "[%s] %s", logtime, buf);
					sock_write (con->sock, "->");
				}
			}
		}
	} else if (info.console_mode != CONSOLE_LOG) {
		fprintf (stderr, "[%s] %s\n", logtime, buf);
	}
	
	va_end (ap);
}

void 
xa_debug (int level, char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	char logtime[100];
	avl_traverser trav = {0};
	connection_t *con;
	admin_t *admin;
	mythread_t *mt;
#ifdef NTRIP_NUMBER
	return;
#endif
	mt = thread_check_created ();

	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);

	if (!mt) fprintf (stderr, "WARNING: No mt while outputting [%s]", buf);
  
	get_log_time(logtime);

	if (!mt) {
		return;
	}

#ifdef DEBUG_FULL
	fprintf (stderr, "\r[%s] [%ld:%s] %s\n", logtime, mt->id, nullcheck_string (mt->name), buf);
#endif

	if (strstr (buf, "%s") != NULL) {
		fprintf (stderr, "WARNING, xa_debug() called with '%%s' formatted string [%s]!", buf);
		return;
	}


	if (info.logfiledebuglevel >= level) {
		if (info.logfile != -1) {
//			thread_mutex_lock(&info.logfile_mutex);
			fd_write (info.logfile, "[%s] [%ld:%s] %s\n", logtime, mt->id, nullcheck_string (mt->name), buf);
//			thread_mutex_unlock(&info.logfile_mutex);
		}
	}

	if (info.consoledebuglevel >= level)
		if (info.console_mode == CONSOLE_LOG) {
			printf("\r[%s] [%ld:%s] %s\n", logtime, mt->id, nullcheck_string (mt->name), buf);
			fflush(stdout);
		}
	
	if (is_server_running()) {
		while ((con = avl_traverse(info.admins, &trav)) != NULL) {
			admin = (admin_t *)con->food.admin;
			if (con->type != admin_e) {
				printf("ERROR IN TYPE in id %ld\n", con->id);
				continue;
			}
			if (admin->tailing && admin->alive && (admin->debuglevel >= level)) {
				if (ntripcaster_strcmp (con->host, "NtripCaster console") == 0)
				{
					printf ("[%s] [%ld:%s] %s\n-> ", logtime, mt->id, nullcheck_string (mt->name), buf);
					fflush (stdout);
				} 
				else
				{
					sock_write_line (con->sock, "[%s] %s", logtime, buf);
					sock_write (con->sock, "-> ");
				}
			}
		}
	} else {
		if (info.consoledebuglevel >= level)
			fprintf (stderr, "[%s] %s\n", logtime, buf);
	}
	
	va_end (ap);
}

/*
void
stats_write_html (server_info_t *info)
{
	int fd, outfd;
	char template_file[BUFSIZE];
	char *logfilename = get_log_file (info->statshtmlfilename);
	char timebuf[BUFSIZE];
	statistics_t stat;
	avl_tree *variables;
	
	if ((get_ntripcaster_file ("statistics.html", template_file_e, R_OK, template_file) == NULL) || ((fd = open_for_reading (template_file)) == -1))
	{
		xa_debug (1, "DEBUG: stats_write_html(): Couldn't open template file");
//		nfree (template_file);
		nfree (logfilename);
		return;
	}
	
	fd_close (fd);
	
	outfd = open_for_writing (logfilename);
	
	if (outfd < 0)
	{
		xa_debug (1, "WARNING: Could not create logfile for html statistics");
//		nfree (template_file);
		nfree (logfilename);
		return;
	}

	// Collect statistics
	get_running_stats (&stat);
	variables = avl_create (compare_vars, &info);

	add_varpair2 (variables, nstrdup ("TOTAL_READ"), ntripcaster_utoa (stat.read_kilos));
	add_varpair2 (variables, nstrdup ("TOTAL_WRITTEN"), ntripcaster_utoa (stat.write_kilos));
	add_varpair2 (variables, nstrdup ("SOURCE_CONNECTIONS"), ntripcaster_utoa (stat.source_connections));
	add_varpair2 (variables, nstrdup ("CLIENT_CONNECTIONS"), ntripcaster_utoa (stat.client_connections));
	add_varpair2 (variables, nstrdup ("AVERAGE_LISTENER_TIME"), nstrdup (connect_average (stat.client_connect_time, stat.client_connections, timebuf)));

// write_megs durch write_kilos ersetzt. ajd 
	add_varpair2 (variables, nstrdup ("AVERAGE_LISTENER_TRANSFER"), ntripcaster_utoa (transfer_average (stat.write_kilos, stat.client_connections)));
	add_varpair2 (variables, nstrdup ("AVERAGE_SOURCE_TIME"), nstrdup (connect_average (stat.source_connect_time, stat.source_connections, timebuf)));

// read_megs durch read_kilos ersetzt
	add_varpair2 (variables, nstrdup ("AVERAGE_SOURCE_TRANSFER"), ntripcaster_utoa (transfer_average (stat.read_kilos, stat.source_connections)));

	xa_debug (3, "DEBUG: Parsing statistics template file %s", template_file);
	
	write_template_parsed_html_page (NULL, NULL, template_file, outfd, variables);
	fd_close (outfd);
//	nfree (template_file);
	nfree (logfilename);
}
*/

/*
void 
stats_write(server_info_t *info)
{
	time_t uptime, t = get_time ();
	char *logfilename = get_log_file (info->statsfilename);
	//char *clisrcname = get_log_file (info->clisrcfilename);
	statistics_t stat;
	char timebuf[BUFSIZE];

	if (!logfilename)
	{
		xa_debug (1, "WARNING: Could not find a valid logfile for statistics, skipping write");
		return;
	}

	if ((info->statsfile = open_for_writing (logfilename)) == -1)
	{
		write_log(LOG_DEFAULT, "WARNING: Could not open stats logfile %s for writing", logfilename ? logfilename : "null");
	} else {
		// Dump uptime information
		uptime = t - info->server_start_time;
		fd_write (info->statsfile, "NtripCaster %s server uptime: %s\n", VERSION, nntripcaster_time (uptime, timebuf));

		if (info->location)
			fd_write (info->statsfile, "NtripCaster server location: %s\n", info->location);
		
		if (info->rp_email)
			fd_write (info->statsfile, "Resposible person: %s\n", info->rp_email);

		
		// Dump admin information
		fd_write (info->statsfile, "Listing admins (%lu):\n", info->num_admins);
		avl_walk (info->admins, print_admin, NULL);

		// Dump sources information
		fd_write (info->statsfile, "Listing sources (%lu):\n", info->num_sources);
		avl_walk(info->sources, print_source_verbose, NULL);

		// Dump listener information
		fd_write (info->statsfile, "Listing listeners (%lu):\n", info->num_clients);
		avl_walk(info->clients, print_client, NULL);

		get_running_stats (&stat);
		
		fd_write(info->statsfile, "Displaying server statistics since last resync:\n");
		fd_write(info->statsfile, "Total KBytes read: %lu\n", stat.read_kilos);
		fd_write(info->statsfile, "Total KBytes written: %lu\n", stat.write_kilos);
		fd_write(info->statsfile, "Number of source connects: %lu\n", stat.source_connections);
		fd_write(info->statsfile, "Number of client connects: %lu\n", stat.client_connections);

		if (stat.client_connections > 0) {
			fd_write(info->statsfile, "Average listener time: %s\n", connect_average (stat.client_connect_time, stat.client_connections, timebuf));
			fd_write(info->statsfile, "Average listener transfer: %lu KBytes\n", transfer_average (stat.write_kilos, stat.client_connections));
		}
		if (stat.source_connections > 0) {
			fd_write(info->statsfile, "Average source connect time: %s\n", 
				connect_average (stat.source_connect_time, stat.source_connections, timebuf));
			fd_write(info->statsfile, "Average source transfer: %lu KBytes\n", transfer_average (stat.read_kilos, stat.source_connections));
		}

		fd_close(info->statsfile);
	}
	nfree (logfilename);

// write to client/source logfile. ajd

	if (!clisrcname)
	{
		xa_debug (1, "WARNING: Could not find a valid logfile for client/source, skipping write");
		return;
	}

	if ((info->clisrcfile = open_for_append (clisrcname)) == -1)
	{
		write_log(LOG_DEFAULT, "WARNING: Could not open client/source logfile %s for writing", info->clisrcfilename ? info->clisrcfilename : "null");
	} else {
		fd_write(info->clisrcfile, "%lu %lu %lu\n", info->statscount, info->num_clients, info->num_sources);
		info->statscount++;

		fd_close(info->clisrcfile);
	}
	nfree (clisrcname);

}
*/

void clear_logfile(char *logfilename) {

	char *filename;
	int fd;

	filename = get_log_file (logfilename);
	fd = open_for_writing(filename);
	if (fd) fd_close(fd);

	nfree(filename);
}

void open_log_files() {
#ifdef CHANGE5
	char *acsfilename;
	int new = 0;

	thread_mutex_lock(&info.logfile_mutex);

	info.logfile = open_log_file(info.logfilename, info.logfile);
	info.usagefile = open_log_file(info.usagefilename, info.usagefile);

	acsfilename = get_log_file(info.accessfilename);
	if (access (acsfilename, R_OK) < 0) new = 1;
	free(acsfilename);

	info.accessfile = open_log_file(info.accessfilename, info.accessfile);

	if ((info.accessfile != -1) && (new == 1)) fd_write_line (info.accessfile, "Date,Time,User,IP,Station,Client,Seconds,Bytes"); // write first line, if file is new. ajd

#else
	thread_mutex_lock(&info.logfile_mutex);

	info.logfile = open_log_file(info.logfilename, info.logfile);
	info.accessfile = open_log_file(info.accessfilename, info.accessfile);
	info.usagefile = open_log_file(info.usagefilename, info.usagefile);
#endif

	thread_mutex_unlock(&info.logfile_mutex);
}

/* Opens the ntripcaster server logfiles. If it fails, let the user know, but let
   the show go on. Having an open logfile is something the server can
   live without */
int open_log_file(char *name, int oldfd)
{
	char *logfile;
	int outfd;

	if (!name) return -1;

	logfile = get_log_file(name);
	
	if (!logfile) return -1;
	
	if (oldfd != -1) {
//		unlock_file(oldfd);
		close(oldfd);
	}

	outfd = open_for_append(logfile);
	
	if (outfd == -1) {
		nfree(logfile); // added. ajd
//		write_log(LOG_DEFAULT, "WARNING: Could not open logfile %s for writing!", logfile ? logfile : "null");
		return -1;
	}
	
//	if (lock_file(outfd) < 0) write_log(LOG_DEFAULT, "WARNING: Could not lock logfile %s for writing!", logfile ? logfile : "null");

//	xa_debug(1, "DEBUG: Using logfile %s [fd %d] for %s", logfile, outfd, name);
	
	nfree(logfile);

	return outfd;
}

int
fd_write_bytes (int fd, const char *buff, const int len)
{
	if (!buff) {
		xa_debug (1, "ERROR: fd_write_bytes() called with NULL data");
		return -1;
	} else if (len <= 0) {
		xa_debug (1, "ERROR: fd_write_bytes() called with zero or negative len");
		return -1;
	}
	
	return write (fd, buff, len);
}

int
fd_write_line (int fd, const char *fmt, ...)
{
	char buff[BUFSIZE];
	va_list ap;
	
	va_start(ap, fmt);
	vsnprintf(buff, BUFSIZE, fmt, ap);
	return fd_write (fd, "%s\n", buff);
}

int 
fd_write (int fd, const char *fmt, ...)
{
	char buff[BUFSIZE];
	va_list ap;
	
	va_start(ap, fmt);
	vsnprintf(buff, BUFSIZE, fmt, ap);
	va_end (ap);
	
	if (fd == 1 || fd == 0) {
		if (is_server_running() && ((info.console_mode == CONSOLE_ADMIN) || (info.console_mode == CONSOLE_ADMIN_TAIL))) {
			fprintf(stdout, "%s", buff);
			fflush(stdout);
			return 1;
#ifndef _WIN32
		} else {
			return write(fd, buff, ntripcaster_strlen(buff));
		}
#else
		}	
#endif
        } else {
		return write(fd, buff, ntripcaster_strlen(buff));
	}
    return 0;
}

/*
 * Read one line of at max len bytes from sockfd into buff.
 * If ok, return 1 and nullterminate buff. Otherwize return 0.
 * Terminating \n is not put into the buffer.
 * Assert Class: 2
 */
int 
fd_read_line (int fd, char *buff, const int len)
{
	char c = '\0';
	int read_bytes, pos;

	buff[len-1] = ' ';

       /* Hint, don't press tab here ;) */
       if (!buff) {
          xa_debug (1, "ERROR: fd_read_line () called with NULL storage pointer");
          return 0;
	} else if (len <= 0) {
	  xa_debug (1, "ERROR: fd_read_line () called with invalid length");
	  return 0;
	}

	pos = 0;
	read_bytes = read (fd, &c, 1);

        if (read_bytes < 0)
	{
		xa_debug (1, "DEBUG: read error on file descriptor %d [%d]", fd, errno);
		return 0;
	}

/** the length of the buff array is len, but its adress range is from 0 to len-1.
 * if pos = len the while loop exits, but then there is another access to
 * buff[pos] = buff[len] which must fail (segmentation fault), so test it before. ajd
 */

	while ((c != '\n') && (pos < len) && (read_bytes == 1)) {
		if (c != '\r')
                     buff[pos++] = c;
		read_bytes = read (fd, &c, 1);
	}

	if (pos < len)
		buff[pos] = '\0';
	else {
		buff[len-1] = '\0';
		xa_debug(1, "ERROR: read line too long (exceeding BUFSIZE)");
		return 0;
	}

	return ((pos > 0) || (c == '\n')) ? 1 : 0;
}

int
fd_read_line_nb (int fd, char *buff, const int len)
{
	char c = '\0';
	int read_bytes, pos;

	buff[len-1] = ' ';
	
	/* Hint, don't press tab here ;) */
	if (!buff) {
		xa_debug (1, "ERROR: fd_read_line_nb () called with NULL storage pointer");
		return 0;
	} else if (len <= 0) {
		xa_debug (1, "ERROR: fd_read_line_nb () called with invalid length");
		return 0;
	}
	
	read_bytes = pos = 0;

	do
	{
		read_bytes = read(fd, &c, 1);

		if (read_bytes < 0) {
			if (!is_recoverable(errno)) {
				xa_debug(1, "DEBUG: read error on file descriptor %d [%s]", fd, strerror(errno));
				return 0;
			} else {
				my_sleep(30000);
			}
		}

		/* EOF -- errno not set */
		if (read_bytes == 0)
			break;

		if (c != '\r' && read_bytes > 0)
			buff[pos++] = c;

	} while (pos < len && c != '\n');

// added (for reason see above). ajd
	if (pos < len)
		buff[pos] = '\0';
	else {
		buff[len-1] = '\0';
		xa_debug(1, "ERROR: read line too long (exceeding BUFSIZE)");
		return 0;
	}

	return ((pos > 0) || (c == '\n')) ? 1 : 0;
}

int
fd_close (int fd)
{
	if (fd < 2)
		xa_debug (1, "DEBUG: Closing fd %d", fd);
	else
		xa_debug (1, "DEBUG: Closing fd %d", fd);

	if (fd >= 0) {
		return close (fd);
	}
	else
		return -1;
}


void 
write_to_logfile (int whichlog, char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	char logtime[100];
	mythread_t *mt = thread_check_created ();
	int fd = get_log_fd (whichlog);

	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZE, fmt, ap);
  
	if (!mt) fprintf (stderr, "WARNING: No mt while outputting [%s]", buf);

	get_log_time(logtime);

	if (strstr (buf, "%s") != NULL) {
		fprintf (stderr, "WARNING, write_log () called with '%%s' formatted string [%s]!", buf);
		return;
	}
	
	if (mt && (fd > -1)) {
		thread_mutex_lock(&info.logfile_mutex);
		fd_write (fd, "[%s] [%d:%s] %s\n", logtime, mt->id, nullcheck_string (mt->name), buf);
		thread_mutex_unlock(&info.logfile_mutex);
	}

	va_end (ap);
}


