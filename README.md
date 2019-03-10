# htprotect-wordpress
While WordPress has an authentication system of its own, some opt to add additional server-side password protection to /wp-admin/ using basic authentication. This prompts users for a username and a password before even allowing access to the admin files and WordPress authentication. WordPress cautions that password protecting /wp-admin/ itself can break some WordPress functionality and plugins using AJAX. While the password protection can be configured to allow AJAX to bypass authentication, they suggest that password protecting wp-login.php is sufficient for most cases.  

https://www.nginx.com/resources/wiki/start/topics/recipes/wordpress/  
https://blog.rudeotter.com/password-protect-wordpress-admin-directory-nginx/

# NGINX Configuration
/etc/nginx/sites-available/example.com
```
upstream php {
  server unix:/var/run/php/php7.2-fpm.sock;
  server 127.0.0.1:9000;
}

server {
  server_name example.com www.example.com;
  root /var/www/example;
  index index.php;

 location = /wp-login.php {
    auth_basic "Authorization Required";
    auth_basic_user_file /var/www/example/.htpasswd;
    include snippets/fastcgi-php.conf;
    fastcgi_intercept_errors on;
    fastcgi_pass php;
  }
  location /wp-admin {
    location ~ /wp-admin/admin-ajax.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_intercept_errors on;
      fastcgi_pass php;
    }
    location ~* /wp-admin/.*\.php$ {
      auth_basic "Authorization Required";
      auth_basic_user_file  /var/www/example/.htpasswd;
      include snippets/fastcgi-php.conf;
      fastcgi_intercept_errors on;
      fastcgi_pass php;
    }
  }
  location = /favicon.ico {
    log_not_found off;
    access_log off;
  }
  location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
  }
  location / {
    try_files $uri $uri/ /index.php?$args;
  }
  location ~ \.php$ {
    #NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
    include snippets/fastcgi-php.conf;
    fastcgi_intercept_errors on;
    fastcgi_pass php;
  }
  location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires max;
    log_not_found off;
  }
  # SSL - certbot will generate this for you, below is a pure example.
  # https://letsencrypt.org/getting-started/
  # https://certbot.eff.org/
  #
  #  listen 443 ssl; # managed by Certbot
  #  ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; # managed by Certbot
  #  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; # managed by Certbot
  #  include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
  #  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

#server {
#       if ($host = www.example.com) {
#        return 301 https://$host$request_uri;
#       } # managed by Certbot
#      
#       if ($host = example.com) {
#           return 301 https://$host$request_uri;
#       } # managed by Certbot
#
#       listen 80;
#       server_name example.com www.example.com;
#       return 404; # managed by Certbot
#}
```
Verify we're all set and good to go
```
$ sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```
Reload nginx
```
$ sudo service nginx reload
```
