FROM php:7.4-apache
COPY php.ini /usr/local/etc/php/conf.d/hardening.ini

COPY challenge/ /var/www/html/

CMD ["/bin/sh", "-c", "php -S 0.0.0.0:1337 2> /dev/null"]

