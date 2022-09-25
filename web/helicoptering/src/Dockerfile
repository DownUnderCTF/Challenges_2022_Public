FROM httpd:2.4

COPY . /usr/local/apache2/htdocs/

RUN sed -i 's/AllowOverride None/AllowOverride All/g' /usr/local/apache2/conf/httpd.conf \
  && sed -i '/LoadModule rewrite_module/s/^#//g' /usr/local/apache2/conf/httpd.conf \
  && sed -i 's/Listen 80/Listen 1337/g' /usr/local/apache2/conf/httpd.conf \
  && { \
    echo 'IncludeOptional conf.d/*.conf'; \
  } >> /usr/local/apache2/conf/httpd.conf \
  && mkdir /usr/local/apache2/conf.d
