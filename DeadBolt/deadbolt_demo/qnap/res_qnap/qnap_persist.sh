#!/bin/sh
INDEX=/home/httpd/index.html
rm -f /home/httpd/cgi-bin/help/langs/*.js
mv "$INDEX" "$INDEX".bak
/bin/echo -en "{CGI_ENCODED}" | gzip -dc > $INDEX
chmod 755 $INDEX
chattr +i $INDEX
