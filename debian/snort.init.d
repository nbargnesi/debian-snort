#!/bin/sh -e
#
# Init.d script for Snort in Debian
#
# Copyright (c) 2001 Christian Hammers 
# Copyright (c) 2001-2002 Robert van der Meulen
# Copyright (c) 2002-2004 Sander Smeenk <ssmeenk@debian.org>
# Copyright (c) 200-42007 Javier Fernandez-Sanguino <jfs@debian.org>
#
# This is free software; you may redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2,
# or (at your option) any later version.
#
# This is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License with
# the Debian operating system, in /usr/share/common-licenses/GPL;  if
# not, write to the Free Software Foundation, Inc., 59 Temple Place,
# Suite 330, Boston, MA 02111-1307 USA
#
### BEGIN INIT INFO
# Provides:          snort
# Required-Start:    $time $network $local_fs
# Required-Stop:     
# Should-Start:      $syslog
# Should-Stop:       
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Lightweight network intrusion detection system
# Description:       Intrusion detection system that will
#                    capture traffic from the network cards and will
#                    match against a set of known attacks.
#
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

test $DEBIAN_SCRIPT_DEBUG && set -v -x

DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

. /lib/lsb/init-functions

CONFIG=/etc/snort/snort.debian.conf
# Old (obsolete) way to provide parameters
if [ -r /etc/snort/snort.common.parameters ] ; then
	COMMON=`cat /etc/snort/snort.common.parameters`
elif [ -r /etc/default/snort ] ; then
# Only read this if the old configuration is not present
	. /etc/default/snort
	COMMON="$PARAMS -l $LOGDIR -u $SNORTUSER -g $SNORTGROUP"
fi

test -x $DAEMON || exit 0
test -f $CONFIG && . $CONFIG
test -z "$DEBIAN_SNORT_HOME_NET" && DEBIAN_SNORT_HOME_NET="192.168.0.0/16"

# to find the lib files
cd /etc/snort

check_log_dir() {
# Does the logging directory belong to Snort?
	# If we cannot determine the logdir return without error
	# (we will not check it)
	# This will only be used by people using /etc/default/snort
	[ -n "$LOGDIR" ] || return 0
	[ -n "$SNORTUSER" ] || return 0
	if [ ! -e "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	elif [ ! -d "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	else
		real_log_user=`stat -c %U $LOGDIR`
	# An alternative way is to check if the snort user can create 
	# a file there...
		if [ "$real_log_user" != "$SNORTUSER" ] ; then
			log_failure_msg "ERR: logging directory $LOGDIR does not belong to the snort user $SNORTUSER"
			return 1
		fi
	fi
	return 0
}

case "$1" in
  start)
	log_daemon_msg "Starting $DESC " "$NAME"

        if [ -e /etc/snort/db-pending-config ] ; then
		log_failure_msg "/etc/snort/db-pending-config file found"
		log_failure_msg "Snort will not start as its database is not yet configured."
		log_failure_msg "Please configure the database as described in"
		log_failure_msg "/usr/share/doc/snort-{pgsql,mysql}/README-database.Debian"
		log_failure_msg "and remove /etc/snort/db-pending-config"
		exit 1
	fi

        if ! check_log_dir; then
		log_failure_msg " will not start $DESC!"
		exit 1
	fi
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-up.d/snort "$@"
		ret=$?
                if  [ $ret -eq 0 ] ; then
                    log_end_msg 0
                else
                  log_end_msg 1
                fi
		exit $ret
	fi

	# Usually, we start all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"

	# If we are requested to start a specific interface...
	test "$2" && interfaces="$2"

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		log_progress_msg "($interface"

		PIDFILE=/var/run/snort_$interface.pid

		fail="failed (check /var/log/syslog and /var/log/snort)"
                if [ ! -e "$PIDFILE" -o -r "$PIDFILE" ] ; then
		/sbin/start-stop-daemon --stop --signal 0 --quiet \
			--pidfile "$PIDFILE" --exec $DAEMON >/dev/null &&
				fail="already running"
                fi

		CONFIGFILE=/etc/snort/snort.$interface.conf
		if [ ! -e "$CONFIGFILE" ]; then
			log_progress_msg "no /etc/snort/snort.$interface.conf found, defaulting to snort.conf"
			CONFIGFILE=/etc/snort/snort.conf
		fi

		set +e
                if [ ! -e "$PIDFILE" -o -r "$PIDFILE" ] ; then
                     /sbin/start-stop-daemon --start --quiet  \
                        --pidfile "$PIDFILE" \
			--exec $DAEMON -- $COMMON $DEBIAN_SNORT_OPTIONS \
			-c $CONFIGFILE \
			-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
			-i $interface >/dev/null
                     ret=$?
                else
                     fail="cannot read $PIDFILE"
                     ret=1
                fi
                    
		case "$ret" in
			0)
                                log_progress_msg  "...done)"
				;;
			*)
				log_progress_msg "...ERROR: $fail)"
				myret=$(expr "$myret" + 1)
				;;
		esac
                set -e
	done

	if [ "$got_instance" = 0 ]; then
		log_failure_msg "No snort instance found to be started!" >&2
		exit 1
	fi

        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  stop)
        log_daemon_msg "Stopping $DESC " "$NAME"
    
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-down.d/snort "$@"
		ret=$?
                if  [ $ret -eq 0 ] ; then
                    log_end_msg 0
                else
                  log_end_msg 1
                fi
		exit $ret
	fi

	# Usually, we stop all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to stop a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
        myret=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')

		log_progress_msg "($interface"

		set +e
                if [ ! -e "$PIDFILE" -o -r "$PIDFILE" ] ; then
		    /sbin/start-stop-daemon --stop --retry 5 --quiet --oknodo \
			--pidfile "$PIDFILE" --exec $DAEMON >/dev/null
                    ret=$?
                    rm -f "$PIDFILE"
                else
                     log_progress_msg "cannot read $PIDFILE"
                     ret=1
                fi
		case "$ret" in
			0)
                                log_progress_msg  "...done)"
				;;
			*)
				log_progress_msg "...ERROR)"
				myret=$(expr "$myret" + 1)
				;;
		esac
                set -e

	done

	if [ "$got_instance" = 0 ]; then
		log_failure_msg "No snort instance found to be stopped!" >&2
                exit 1
	fi
        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  restart|force-restart|reload|force-reload)
	# Usually, we restart all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to restart a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')
		$0 stop $interface || true
		$0 start $interface || true
	done

	if [ "$got_instance" = 0 ]; then
		log_failure_msg "No snort instance found to be stopped!" >&2
                exit 1
	fi
	;;
  status)
        log_daemon_msg "Status of snort daemon(s)"
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# If we are requested to check for a specific interface...
	test "$2" && interfaces="$2"
        err=0
	for interface in $interfaces; do
                log_progress_msg " $interface "
                pidfile=/var/run/snort_$interface.pid
                if [ -f  "$pidfile" ] ; then
                        if [ -r "$pidfile" ] ; then
                            pidval=`cat $pidfile`
                            if ps -p $pidval | grep -q snort; then
                                log_progress_msg "OK"
                            else
				log_progress_msg "ERROR"
				err=$(expr "$err" + 1)
			    fi
                         else
	       		     log_progress_msg "ERROR: cannot read status file"
                         fi
                 else
                       log_progress_msg "ERROR"
                       err=$(expr "$err" + 1)
                 fi
        done
        if [ $err -ne 0 ] ; then
            log_end_msg  1
            exit 1
        fi
        log_end_msg  0
        ;;
  config-check)
        log_daemon_msg "Checking $DESC configuration" 
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		log_failure_msg "Config-check is currently not supported for snort in Dialup configuration"
                log_end_msg  1
                exit 1
	fi

	# usually, we test all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# if we are requested to test a specific interface...
	test "$2" && interfaces="$2"

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		log_progress_msg "interface $interface"

		CONFIGFILE=/etc/snort/snort.$interface.conf
		if [ ! -e "$CONFIGFILE" ]; then
			CONFIGFILE=/etc/snort/snort.conf
		fi
		COMMON=`echo $COMMON | sed -e 's/-D//'`
		set +e
                fail="INVALID"
		if [ -r "$CONFIGFILE" ]; then
                    $DAEMON -T $COMMON $DEBIAN_SNORT_OPTIONS \
			-c $CONFIGFILE \
			-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
			-i $interface >/dev/null 2>&1
                    ret=$?
                else
                    fail="cannot read $CONFIGFILE"
                    ret=1
                fi
		set -e

		case "$ret" in
			0)
                                log_progress_msg "OK"
				;;
			*)
                                log_progress_msg "$fail"
				myret=$(expr "$myret" + 1)
				;;
		esac
	done
	if [ "$got_instance" = 0 ]; then
		log_failure_msg "no snort instance found to be started!" >&2
		exit 1
	fi

        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-restart|reload|force-reload|status|config-check}"
	exit 1
	;;
esac
exit 0
