#!/bin/sh -e

test $DEBIAN_SCRIPT_DEBUG && set -v -x
test -f /usr/sbin/snort || exit 0

DAEMON=/usr/sbin/snort
CONFIG=/etc/snort/snort.debian.conf
PPPENV=/var/tmp/snort.ppp.startup.env

test -f $CONFIG && . $CONFIG
test -z "$DEBIAN_SNORT_HOME_NET" && DEBIAN_SNORT_HOME_NET="192.168.0.0/16"

# to find the lib files
cd /etc/snort

case "$1" in
  start)
  	# Do not start snort when startup mode is 'dialup'
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ] && [ "$2" != "logrotate" ]; then
		if [ -e $PPPENV ]; then
			. $PPPENV
			PPP_PID=`pidof pppd`
			if [ "x$PPP_PID" == "x$SNORT_PPP_PID" ]; then
				/etc/ppp/ip-up.d/snort
			else
				echo "The PID Snort stored as the pppd PID ($SNORT_PPP_PID) does not"
				echo "match the PID from the current pppd ($PPP_PID)."
				echo "Please remove $PPPENV"
				echo "and use /etc/ppp/ip-up.d/snort to start snort again."
			fi
		fi
	fi
		
	echo -n "Starting Network Intrusion Detection System: snort"
	set +e
#	/sbin/start-stop-daemon --start --quiet --exec $DAEMON -- \
#		-m 027 \
#		-D \
#		-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
#		-c /etc/snort/snort.conf \
#		-l /var/log/snort \
#		-d \
#		-u snort \
#		-g snort \
#		$DEBIAN_SNORT_OPTIONS >/dev/null
        for sensor in /etc/snort/snort.eth*.conf ; do
                iface=`echo $sensor | cut -d . -f 2`
		echo -n " ($iface interface) "
		/sbin/start-stop-daemon --start --quiet  \
                --pidfile  /var/run/snort_$iface.pid \
		--exec $DAEMON -- \
		-m 027 \
		-D \
		-i $iface \
		-c /etc/snort/snort.$iface.conf \
		-l /var/log/snort/$iface \
		-d \
		-u snort \
		-g snort \
		$DEBIAN_SNORT_OPTIONS >/dev/null
		case "$?" in
		  0) echo "." ;;
		  1) echo "...failed. (check /var/log/daemon.log!)" ;;
		esac
		sleep 3
        done

	set -e
	;;
	
  stop)
	echo -n "Stopping Network Intrusion Detection System: snort"
    /sbin/start-stop-daemon --stop --quiet --oknodo --exec $DAEMON >/dev/null
	# If it isn't willing we shoot it!
	if ls /var/run/snort_*pid >/dev/null 2>&1 ; then
	  sleep 3
	  ps ax \
	  	| grep '/usr/sbin/snort' \
		| grep -v grep \
		| awk '{ print $1 }' \
	  	| xargs --no-run-if-empty kill -9 >/dev/null
	  rm -f /var/run/snort_*.pid
	fi
       	echo "."
	;;
  restart|force-restart|reload|force-reload)

	# Look for any running snort instances
	SNORTISRUNNING=0
	SNORTPID=0
	
	TRY=`ps ax | grep "\(\[snort\]\|/usr/sbin/snort\)" | grep -v grep | awk '{print $1}'`
	if [ "x$TRY" != "x" ]; then
		if kill -0 $TRY; then
			SNORTISRUNNING=1
			SNORTPID=$TRY
		fi
	fi

	# Stop them
 	/etc/init.d/snort stop
	
	# Decide wether we start them again.
  	if [ "$DEBIAN_SNORT_STARTUP" != "boot" ] && [ "$SNORTISRUNNING" = "1" ]; then
		if [ "$DEBIAN_SNORT_STARTUP" = "manual" ]; then
			/etc/init.d/snort start
		fi
		if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
			/etc/ppp/ip-up.d/snort
		fi
	fi
	
	# Always start if startup set to 'boot'
	if [ "$DEBIAN_SNORT_STARTUP" = "boot" ]; then
		/etc/init.d/snort start
	fi

    ;;
  status)
   	echo -n "Status of snort daemon(s):"
        for sensor in /etc/snort/snort.eth*.conf ; do
                iface=`echo $sensor | cut -d . -f 2`
                echo -n " $iface "
                pidfile=/var/run/snort_$iface.pid
		if [ -f  "$pidfile" ] ; then
                pidval=`cat $pidfile`
                if [ -n "`ps ax -o pid | grep $pidval`" ] ; then
                        echo -n "(ok)"
                else
                        echo -n "(nok!)"
                fi
		else
                        echo -n "(nok!)"
		fi
        done
        echo "."
        ;;
   *)
	echo "Usage: /etc/init.d/snort start|stop|restart|reload|status"
	exit 1
       	;;
esac
exit 0
