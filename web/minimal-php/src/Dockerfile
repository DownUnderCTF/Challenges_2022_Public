FROM php:8.1-apache

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" && \
    sed -i 's/^log_errors = On$/log_errors = Off/' "$PHP_INI_DIR/php.ini"

COPY index.php /var/www/html/index.php
COPY flag /flag

CMD ["/bin/sh", "-c", "php -S 0.0.0.0:1337 2> /dev/null"]