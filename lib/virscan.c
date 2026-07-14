/*****************************************************************************
 *
 * Purpose ...............: Scan a file for virusses
 *
 *****************************************************************************
 * Copyright (C) 1997-2011
 *   
 * Michiel Broek		FIDO:		2:280/2802
 * Beekmansbos 10
 * 1971 BV IJmuiden
 * the Netherlands
 *
 * This file is part of MBSE BBS.
 *
 * This BBS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * MBSE BBS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MBSE BBS; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *****************************************************************************/

#include "mbselib.h"


extern pid_t	mypid;


/*
 * ClamAV stream check.
 * Original written bu Laurent Wacrenier as part of the
 * clamd-stream-client.
 * Returns: 0 = Ok, no virus found.
 *          1 = Virus found.
 *          2 = Internal error.
 */
int clam_stream_check(char *servname, char *servport, char *filename)
{
    struct sockaddr_in	sa_in;
    struct addrinfo	hints, *res = NULL, *p;
    int			s, ss, buf_len = 0, err;
    char		buf[1024], *buf_c, *port_s, *ipver = NULL, ipstr[INET6_ADDRSTRLEN];
    FILE		*fp;

    Syslog('f', "clam_stream_check(%s, %s, %s)", servname, servport, filename);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(servname, servport, &hints, &res)) != 0) {
	WriteError("getaddrinfo(%s:%s): %s\n", servname, servport, gai_strerror(err));
	return 2;
    }

    for (p = res; p != NULL; p = p->ai_next) {
	void	*addr;

	if (p->ai_family == AF_INET) {
	    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	    addr = &(ipv4->sin_addr);
	    ipver = (char *)"IPv4";
	} else {
	    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
	    addr = &(ipv6->sin6_addr);
	    ipver = (char *)"IPv6";
	}
	inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	Syslog('+', "Trying %s %s port %s", ipver, ipstr, servport);

	if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
	    WriteError("$socket()");
	    return 2;
	}

	if (connect(s, p->ai_addr, p->ai_addrlen) == -1) {
	    WriteError("$connect %s port %s", ipstr, servport);
	    p = p->ai_next;
	    close(s);
	} else {
	    break;
	}
    }

    if (p == NULL) {
	WriteError("unable to connect to %s", servname);
	return 2;
    }

#define COMMAND "STREAM\r\n"

    Syslog('f', "snd: %s", printable((char *)COMMAND, 0));
    if (write(s, COMMAND, sizeof(COMMAND)-1) == -1) {
	WriteError("$write()");
	return 2;
    }
    if ((buf_len = read(s, buf, sizeof(buf)-1)) == -1) {
	WriteError("$read()");
	return 2;
    }
    Syslog('f', "got: %s", printable(buf, 0));
	  
    buf[buf_len] = 0;
    if (strncasecmp(buf, "PORT ", sizeof("PORT ") -1) != 0) {
	return 2;
    }
	      
    port_s = buf + sizeof("PORT ") -1;
    while(*port_s == ' ') port_s ++;

    memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
    sa_in.sin_port = htons(strtoul(port_s, NULL, 10));
    sa_in.sin_family = AF_INET;
    ss = socket(PF_INET, SOCK_STREAM, 0);
    if (ss == -1) {
	WriteError("$socket()");
	return 2;
    }

    sa_in.sin_port = htons(strtoul(port_s, NULL, 10));
    if (connect(ss, (struct sockaddr *)&sa_in, sizeof(struct sockaddr_in)) == -1) {
	WriteError("$connect2()");
	return 2;
    }

    if ((fp = fopen(filename, "r")) == NULL) {
	WriteError("$can't open %s", filename);
	return 2;
    }

    while ((buf_len = fread(buf, 1, sizeof(buf), fp)) > 0) {
	if (write(ss, buf, buf_len) == -1) {
	    if (errno == EPIPE)
		break;
	    WriteError("$write2()");
	    fclose(fp);
	    return 2;
	}
    }
    if (buf_len == 0 && ferror(fp)) {
	WriteError("$read2()");
	return 2;
    }
    close(ss);
    fclose(fp);

    if ((buf_len = read(s, buf, sizeof(buf)-1)) == -1) { 
	WriteError("$read3()");
	return 2;
    }
    buf[buf_len] = 0;
    Syslog('f', "res: %s", printable(buf, 0));

    /*  fwrite(buf, 1, buf_len, stderr); */
    buf_c = buf + buf_len;
    while(*buf_c=='\r' || *buf_c == '\r' || *buf_c == ' ')
	buf_c --;
    if (buf_c - buf >= sizeof(" FOUND") && strncasecmp(buf_c - sizeof(" FOUND"), " FOUND", sizeof(" FOUND")-1) == 0) {
	char *buf_s = buf;
	buf_c -= sizeof(" FOUND");
	if (strncasecmp(buf_s, "stream:", sizeof("stream:")-1) == 0) {
	    buf_s += sizeof("stream:")-1;
	    while(*buf_s == ' ') 
		buf_s ++;
	    WriteError("ClamAV stream check, virus found: %.*s", (int)(buf_c - buf_s), buf_s);
	}
	return 1;
    }

    close(s);
    Syslog('f', "clam_stream_check(): no virus found");
    return 0;
}



/*
 * F-Prot stream check.
 * Returns: 0 = Ok, no virus found.
 *          1 = Virus found.
 *          2 = Internal error.
 *
 * telnet localhost 10200
 * SCAN FILE /path/to/file SIZE n
 * stream data
 *   --
 * receive:
 * n <descriptive text> <name of the scanned object>
 * n -= result code, 0 s clean.
 */
int fp_stream_check(char *server, char *port, char *filename)
{
    struct addrinfo hints, *res = NULL, *cur;
    int             filesize, buf_len, s = -1, err;
    char            cmd[PATH_MAX], buf[1024], *endptr, *detail;
    FILE            *fp;
    size_t          offset, remaining;
    ssize_t         written;
    long            result_code;

    if ((server == NULL) || (port == NULL) || (filename == NULL)) {
        WriteError("fp_stream_check: invalid argument");
        return 2;
    }

    Syslog('f', "fp_stream_check(%s, %s, %s)", server, port, filename);
    filesize = file_size(filename);
    if (filesize < 0) {
        WriteError("$can't stat %s", filename);
        return 2;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(server, port, &hints, &res);
    if (err != 0) {
        WriteError("getaddrinfo(%s:%s): %s", server, port, gai_strerror(err));
        return 2;
    }

    for (cur = res; cur != NULL; cur = cur->ai_next) {
        s = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (s == -1)
            continue;
        if (connect(s, cur->ai_addr, cur->ai_addrlen) == 0)
            break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s == -1) {
        WriteError("unable to connect to %s:%s", server, port);
        return 2;
    }

    if (snprintf(cmd, sizeof(cmd), "SCAN STREAM %s SIZE %d\n",
                 filename, filesize) >= (int)sizeof(cmd)) {
        WriteError("fp_stream_check: command is too long");
        close(s);
        return 2;
    }
    Syslog('f', "snd: %s", printable(cmd, 0));
    remaining = strlen(cmd);
    offset = 0;
    while (remaining > 0) {
        written = write(s, cmd + offset, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            WriteError("$write()");
            close(s);
            return 2;
        }
        if (written == 0) {
            WriteError("fp_stream_check: short command write");
            close(s);
            return 2;
        }
        offset += (size_t)written;
        remaining -= (size_t)written;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        WriteError("$can't open %s", filename);
        close(s);
        return 2;
    }

    while ((buf_len = (int)fread(buf, 1, sizeof(buf), fp)) > 0) {
        offset = 0;
        remaining = (size_t)buf_len;
        while (remaining > 0) {
            written = write(s, buf + offset, remaining);
            if (written < 0) {
                if (errno == EINTR)
                    continue;
                WriteError("$write2()");
                fclose(fp);
                close(s);
                return 2;
            }
            if (written == 0) {
                WriteError("fp_stream_check: short data write");
                fclose(fp);
                close(s);
                return 2;
            }
            offset += (size_t)written;
            remaining -= (size_t)written;
        }
    }
    if (ferror(fp)) {
        WriteError("$read %s", filename);
        fclose(fp);
        close(s);
        return 2;
    }
    fclose(fp);

    do {
        buf_len = (int)read(s, buf, sizeof(buf) - 1);
    } while ((buf_len < 0) && (errno == EINTR));
    if (buf_len <= 0) {
        WriteError(buf_len == 0 ? "fp_stream_check: empty response" : "$read()");
        close(s);
        return 2;
    }
    buf[buf_len] = '\0';
    close(s);
    Syslog('f', "got: %s", printable(buf, 0));

    errno = 0;
    result_code = strtol(buf, &endptr, 10);
    if ((errno != 0) || (endptr == buf) || (result_code < 0) ||
        (result_code > INT_MAX)) {
        WriteError("fp_stream_check: malformed scanner response");
        return 2;
    }
    detail = strchr(endptr, '<');
    if (detail == NULL)
        detail = endptr;
    if (result_code != 0) {
        WriteError("F-Prot stream check %s, rc=%ld", printable(detail, 0), result_code);
        return 1;
    }

    Syslog('f', "fp_stream_check(): no virus found");
    return 0;
}



/*
 *  Virusscan on a file.
 */
int VirScanFile(char *filename)
{
    char    		*temp, *stdlog, *errlog, buf[256], *port;
    FILE    		*fp, *lp;
    int	    		vrc, rc = FALSE, has_scan = FALSE;

    temp = calloc(PATH_MAX, sizeof(char));
    snprintf(temp, PATH_MAX, "%s/etc/virscan.data", getenv("MBSE_ROOT"));

    if ((fp = fopen(temp, "r")) == NULL) {
	WriteError("No virus scanners defined");
	free(temp);
	return FALSE;
    }
    fread(&virscanhdr, sizeof(virscanhdr), 1, fp);

    while (fread(&virscan, virscanhdr.recsize, 1, fp) == 1) {
	if (virscan.available && (virscan.scantype == SCAN_EXTERN)) {
	    if (file_exist(virscan.scanner, X_OK) == 0) {
	    	has_scan = TRUE;
	    } else {
		Syslog('+', "Warning: virusscanner %s marked active but not present", virscan.comment);
	    }
	}
	if (virscan.available && (virscan.scantype != SCAN_EXTERN)) {
	    has_scan = TRUE;
	}
    }
    if (!has_scan) {
	Syslog('+', "No active virus scanners, skipping scan");
	fclose(fp);
	free(temp);
	return FALSE;
    }
    
    stdlog = calloc(PATH_MAX, sizeof(char));
    errlog = calloc(PATH_MAX, sizeof(char));
    snprintf(stdlog, PATH_MAX, "%s/tmp/stdlog%d", getenv("MBSE_ROOT"), mypid);
    snprintf(errlog, PATH_MAX, "%s/tmp/errlog%d", getenv("MBSE_ROOT"), mypid);

    fseek(fp, virscanhdr.hdrsize, SEEK_SET);
    while (fread(&virscan, virscanhdr.recsize, 1, fp) == 1) {
        if (virscan.available) {
	    Syslog('+', "Scanning %s with %s", filename, virscan.comment);
	    Altime(3600);
	    switch (virscan.scantype) {
		case SCAN_EXTERN:	if (file_exist(virscan.scanner, X_OK) ==0) {
					    vrc = execute_str(virscan.scanner, virscan.options, filename, (char *)"/dev/null", stdlog, errlog);
					    if (file_size(stdlog)) {
						if ((lp = fopen(stdlog, "r"))) {
						    while (fgets(buf, sizeof(buf) -1, lp)) {
							Striplf(buf);
							Syslog('+', "stdout: \"%s\"", printable(buf, 0));
						    }
						    fclose(lp);
						}
					    }
					    if (file_size(errlog)) {
						if ((lp = fopen(errlog, "r"))) {
						    while (fgets(buf, sizeof(buf) -1, lp)) {
							Striplf(buf);
							Syslog('+', "stderr: \"%s\"", printable(buf, 0));
						    }
						    fclose(lp);
						}
					    }
					    unlink(stdlog);
					    unlink(errlog);
					    if (vrc != virscan.error) {
						WriteError("Virus found by %s", virscan.comment);
						rc = TRUE;
					    }
					}
					break;
		case CLAM_STREAM:	port = calloc(21, sizeof(char));
					snprintf(port, 20, "%d", virscan.port);
					if ((clam_stream_check(virscan.host, port, filename) == 1)) {
					    rc = TRUE;
					}
					free(port);
					break;
		case FP_STREAM:		port = calloc(21, sizeof(char));
					snprintf(port, 20, "%d", virscan.port);
					if ((fp_stream_check(virscan.host, port, filename) == 1)) {
					    rc = TRUE;
					}
					free(port);
					break;
	    }

	    Altime(0);
	    Nopper();
        }
    }
    fclose(fp);

    free(temp);
    free(stdlog);
    free(errlog);
    return rc;
}


