#!/bin/bash
# 
# Enhanced WordPress Installation Script with Performance and Security Optimizations
# Improved directory structure checks and package installation
# 

# Set text colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "┌───────────────────────────────────────────────┐"
echo "│         ENHANCED WORDPRESS INSTALLER          │"
echo "│     Performance & Security Optimized Setup    │"
echo "└───────────────────────────────────────────────┘"
echo -e "${NC}"

# ======== SYSTEM INFORMATION ========
echo -e "${BLUE}System Information:${NC}"
echo -e "  OS: $(lsb_release -ds)"
echo -e "  Kernel: $(uname -r)"
echo -e "  Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo -e "  Disk Space: $(df -h / | awk 'NR==2 {print $4}') available"
echo -e "  CPU: $(grep -c processor /proc/cpuinfo) cores"
echo

# Check if system meets minimum requirements
total_mem=$(free -m | awk '/^Mem:/ {print $2}')
if [ "$total_mem" -lt 1024 ]; then
  echo -e "${YELLOW}Warning: System has less than 1GB of RAM. WordPress may run slowly.${NC}"
fi

disk_space=$(df -m / | awk 'NR==2 {print $4}')
if [ "$disk_space" -lt 5120 ]; then
  echo -e "${YELLOW}Warning: Less than 5GB of free disk space. This may not be enough for a production site.${NC}"
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo)${NC}"
  exit 1
fi

# Check for required commands
for cmd in curl openssl nginx mysql; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${YELLOW}Command '$cmd' not found. Installing basic requirements...${NC}"
    # apt update
    apt install -y curl openssl
    break
  fi
done


# ======== CLEANUP EXISTING CONFIGURATION ========
echo -e "${BLUE}Cleaning up any existing configuration...${NC}"

# Stop services first
systemctl stop nginx
systemctl stop "php*-fpm" || true
systemctl stop mysql || true
systemctl stop mariadb || true

# Ask for confirmation before removing existing packages
read -p "Do you want to completely remove existing packages? (y/n) [n]: " remove_existing
if [[ "$remove_existing" == "y" || "$remove_existing" == "Y" ]]; then
  echo -e "${YELLOW}Removing existing packages and configurations...${NC}"
  
  # Remove Nginx
  apt purge -y nginx nginx-common nginx-full nginx-core
  
  # Remove PHP
  apt purge -y php* php*-* php*-fpm
  
  # Remove MariaDB but keep databases
  read -p "Remove MariaDB/MySQL? This will DELETE all databases! (y/n) [n]: " remove_db
  if [[ "$remove_db" == "y" || "$remove_db" == "Y" ]]; then
    apt purge -y mariadb-server mariadb-client mysql-server mysql-client
    rm -rf /var/lib/mysql
  fi
  
  # Autoremove dependencies
  apt autoremove -y
  
  # Clean apt
  apt clean
  apt autoclean
  
  # Remove configuration directories
  rm -rf /etc/nginx
  rm -rf /etc/php
fi


# ======== USER INPUTS ========


# Ask which components to install
echo -e "${BLUE}Which components do you want to install?${NC}"
read -p "Install Nginx? (y/n) [y]: " install_nginx
install_nginx=${install_nginx:-y}

read -p "Install MariaDB? (y/n) [y]: " install_mariadb
install_mariadb=${install_mariadb:-y}

read -p "Install PHP? (y/n) [y]: " install_php
install_php=${install_php:-y}

read -p "Install WordPress? (y/n) [y]: " install_wordpress
install_wordpress=${install_wordpress:-y}

read -p "Install SSL certificate? (y/n) [y]: " install_ssl
install_ssl=${install_ssl:-y}

# Domain name with validation
while true; do
  read -p "Enter your domain name (e.g., example.upcode.vn): " domain_name
  if [[ -z "$domain_name" ]]; then
    echo -e "${RED}Domain name cannot be empty. Please try again.${NC}"
  elif [[ ! "$domain_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
    echo -e "${RED}Invalid domain name format. Please try again.${NC}"
  else
    break
  fi
done


# Database password generation
db_password=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)
echo -e "${YELLOW}Generated database password: ${db_password}${NC}"
echo -e "${YELLOW}Please save this password somewhere safe!${NC}"
echo


# SSL email with validation
if [[ "$install_ssl" == "y" || "$install_ssl" == "Y" ]]; then
  while true; do
    read -p "Enter your email for SSL certificates: " ssl_email
    if [[ -z "$ssl_email" ]]; then
      echo -e "${RED}Email cannot be empty. Please try again.${NC}"
    elif [[ ! "$ssl_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
      echo -e "${RED}Invalid email format. Please try again.${NC}"
    else
      break
    fi
  done
fi

# PHP version selection
echo -e "${BLUE}Select PHP version to install:${NC}"
echo "1) PHP 7.4 (Legacy)"
echo "2) PHP 8.0"
echo "3) PHP 8.1"
echo "4) PHP 8.2 (Recommended)"
echo "5) PHP 8.3 (Latest)"
read -p "Enter your choice [4]: " php_choice

# Set default PHP version if no input
if [ -z "$php_choice" ]; then
  php_choice=4
fi

# Map choice to actual PHP version
case $php_choice in
  1) php_version="7.4" ;;
  2) php_version="8.0" ;;
  3) php_version="8.1" ;;
  4) php_version="8.2" ;;
  5) php_version="8.3" ;;
  *) 
    echo -e "${RED}Invalid choice. Using PHP 8.2 as default.${NC}"
    php_version="8.2"
    ;;
esac

echo -e "${GREEN}Will install PHP $php_version${NC}"

# MariaDB version selection
echo -e "${BLUE}Select MariaDB version to install:${NC}"
echo "1) MariaDB 10.6 (Older LTS)"
echo "2) MariaDB 10.11 (Current LTS, Recommended)"
echo "3) MariaDB 11.0 (Latest)"
read -p "Enter your choice [2]: " mariadb_choice

# Set default MariaDB version if no input
if [ -z "$mariadb_choice" ]; then
  mariadb_choice=2
fi

# Map choice to actual MariaDB version
case $mariadb_choice in
  1) mariadb_version="10.6" ;;
  2) mariadb_version="10.11" ;;
  3) mariadb_version="11.0" ;;
  *) 
    echo -e "${RED}Invalid choice. Using MariaDB 10.11 as default.${NC}"
    mariadb_version="10.11"
    ;;
esac

echo -e "${GREEN}Will install MariaDB $mariadb_version${NC}"


# ======== WORDPRESS SETUP ========
if [[ "$install_wordpress" == "y" || "$install_wordpress" == "Y" ]]; then
  # Sử dụng giá trị mặc định thay vì hỏi người dùng
  wp_title="WordPress Site"
  wp_admin_user="admin"
  wp_admin_password=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
  wp_admin_email=${ssl_email:-"admin@${domain_name}"}
  
  echo -e "${YELLOW}WordPress admin credentials:${NC}"
  echo -e "  Username: ${YELLOW}${wp_admin_user}${NC}"
  echo -e "  Password: ${YELLOW}${wp_admin_password}${NC}"
  echo -e "  Email: ${YELLOW}${wp_admin_email}${NC}"
  echo -e "${YELLOW}Please save this information!${NC}"
fi

# ======== INITIAL SETUP ========

# Function to check DNS record
check_dns() {
    local domain=$1
    if nslookup "$domain" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ DNS record for $domain exists and is working.${NC}"
    else
        echo -e "${RED}❌ DNS record for $domain does NOT exist or is not working.${NC}"
        echo -e "${YELLOW}Please add these 2 DNS records first in your DNS Provider: $domain and www.$domain${NC}"
        read -p "Continue anyway? (y/n) [n]: " continue_anyway
        if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
            exit 1
        fi
    fi
}


echo -e "${BLUE}🔍 Checking DNS records for $domain_name and www.$domain_name...${NC}"
check_dns "$domain_name"
check_dns "www.$domain_name"


# Create variables based on the domain name
domain_base=$(echo "$domain_name" | cut -d '.' -f1)
# site_user="${domain_base}_upcode_vn_usr"
site_user="$(echo "$domain_name" | tr '.' '_')_usr"


# Directory structure based on the provided layout
web_root="/var/www/${site_user}/data/${domain_name}"
logs_dir="/var/www/${site_user}/logs"

# Nginx configuration paths exactly as provided
nginx_site_dir="/etc/nginx/sites-available/${site_user}"
nginx_site_config="${nginx_site_dir}/${domain_name}.conf"
nginx_site_enabled="/etc/nginx/sites-enabled/${domain_name}.conf"

# Clean domain name for MySQL (replace invalid characters)
# db_name=$(echo "${domain_base}_upcode_vn" | tr '.-' '_')
db_name=$(echo "${domain_name}" | tr '.-' '_')
db_user="${db_name}_usr"

# Display the variables
echo -e "${BLUE}Configuration variables:${NC}"
echo -e "  Domain: ${YELLOW}${domain_name}${NC}"
echo -e "  Site User: ${YELLOW}${site_user}${NC}"
echo -e "  Web Root: ${YELLOW}${web_root}${NC}"
echo -e "  Database Name: ${YELLOW}${db_name}${NC}"
echo -e "  Database User: ${YELLOW}${db_user}${NC}"
echo

# ======== SYSTEM UPDATES ========

echo -e "${BLUE}Updating system packages...${NC}"
#apt update
# apt upgrade -y

# ======== SOFTWARE INSTALLATION ========

# Add required repositories
echo -e "${BLUE}Adding required repositories...${NC}"
apt install -y software-properties-common
add-apt-repository -y ppa:ondrej/php
add-apt-repository -y ppa:ondrej/nginx

# MariaDB repository
curl -sS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | bash -s -- --mariadb-server-version="$mariadb_version"

# Update after adding repos
# apt update

# Install packages with verification
echo -e "${BLUE}Installing required packages...${NC}"

# Install Nginx with verification
echo -e "${BLUE}Installing Nginx...${NC}"
apt install -y nginx
if ! [ -d "/etc/nginx" ]; then
  echo -e "${RED}Nginx installation failed. Directory /etc/nginx does not exist.${NC}"
  exit 1
fi

# Install other required tools
apt install -y certbot python3-certbot-nginx

# Install MariaDB
echo -e "${BLUE}Installing MariaDB server...${NC}"
apt install -y mariadb-server
if ! systemctl is-active --quiet mariadb; then
  echo -e "${RED}MariaDB installation failed or service not running.${NC}"
  systemctl start mariadb || true
fi

# Install selected PHP version and extensions with verification
echo -e "${BLUE}Installing PHP $php_version and extensions...${NC}"
apt install -y php$php_version-fpm php$php_version-mysql php$php_version-curl php$php_version-gd \
               php$php_version-intl php$php_version-mbstring php$php_version-soap php$php_version-xml \
               php$php_version-zip php$php_version-imagick php$php_version-cli \
               php$php_version-bcmath php$php_version-common php$php_version-opcache

# Verify PHP installation
if ! [ -d "/etc/php/${php_version}/fpm" ]; then
  echo -e "${RED}PHP installation failed. Directory /etc/php/${php_version}/fpm does not exist.${NC}"
  exit 1
fi

# Create necessary directory structure for Nginx if missing
echo -e "${BLUE}Verifying Nginx directory structure...${NC}"
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /etc/nginx/snippets
mkdir -p /etc/nginx/conf.d

# ======== SYSTEM USER SETUP ========

# Create dedicated web user
echo -e "${BLUE}Creating dedicated web user for this site...${NC}"
if id "$site_user" &>/dev/null; then
  echo -e "${YELLOW}User $site_user already exists.${NC}"
else
  adduser --disabled-password --gecos "" "$site_user"
fi

# ======== DIRECTORY SETUP ========

# Create web directories with proper nesting
echo -e "${BLUE}Creating web directories...${NC}"
mkdir -p "$web_root"
mkdir -p "$logs_dir"
mkdir -p "$nginx_site_dir"

# Create Nginx cache directory
mkdir -p /var/run/nginx-cache
chown www-data:www-data /var/run/nginx-cache

# Create webroot verification directory for SSL
mkdir -p "$web_root/.well-known/acme-challenge"
chown -R www-data:www-data "$web_root/.well-known"
chmod -R 755 "$web_root/.well-known"

# ======== DATABASE SETUP ========

echo -e "${BLUE}Setting up MySQL database...${NC}"

# Kiểm tra xem cơ sở dữ liệu có tồn tại không
db_exists=$(mysql -u root -e "SHOW DATABASES LIKE '${db_name}';" | grep -o "${db_name}")

if [ -z "$db_exists" ]; then
  # Cơ sở dữ liệu chưa tồn tại, tạo mới
  echo -e "${GREEN}Creating new database: ${db_name}${NC}"
  mysql -u root -e "CREATE DATABASE ${db_name} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;"
else
  echo -e "${YELLOW}Database ${db_name} already exists${NC}"
fi

# Kiểm tra xem người dùng cơ sở dữ liệu có tồn tại không
user_exists=$(mysql -u root -e "SELECT User FROM mysql.user WHERE User='${db_user}';" | grep -o "${db_user}")

if [ -z "$user_exists" ]; then
  # Người dùng chưa tồn tại, tạo mới
  echo -e "${GREEN}Creating new database user: ${db_user}${NC}"
  mysql -u root -e "CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_password}';"
else
  echo -e "${YELLOW}Database user ${db_user} already exists${NC}"
  # Cập nhật mật khẩu cho người dùng hiện tại
  mysql -u root -e "ALTER USER '${db_user}'@'localhost' IDENTIFIED BY '${db_password}';"
fi

# Luôn cấp quyền, bất kể người dùng đã tồn tại hay mới
echo -e "${GREEN}Granting privileges to database user: ${db_user}${NC}"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Kiểm tra kết nối
echo -e "${BLUE}Testing database connection...${NC}"
if ! mysql -u "$db_user" -p"$db_password" -e "USE ${db_name}; SELECT 1;" >/dev/null 2>&1; then
  echo -e "${RED}Failed to connect to database with new user. Fixing permissions...${NC}"
  mysql -u root -e "DROP USER IF EXISTS '${db_user}'@'localhost';"
  mysql -u root -e "CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_password}';"
  mysql -u root -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost';"
  mysql -u root -e "FLUSH PRIVILEGES;"
  
  # Kiểm tra lại kết nối
  if ! mysql -u "$db_user" -p"$db_password" -e "USE ${db_name}; SELECT 1;" >/dev/null 2>&1; then
    echo -e "${RED}Still unable to connect to database. Please check MySQL configuration.${NC}"
    echo -e "${YELLOW}Installation will continue, but WordPress might not function correctly.${NC}"
  else
    echo -e "${GREEN}Database connection successful after fixing permissions!${NC}"
  fi
else
  echo -e "${GREEN}Database connection successful!${NC}"
fi

# ======== MARIADB OPTIMIZATION ========

echo -e "${BLUE}Optimizing MariaDB for WordPress...${NC}"
mkdir -p /etc/mysql/mariadb.conf.d
cat > /etc/mysql/mariadb.conf.d/99-wordpress-optimizations.cnf << EOF
[mysqld]

# Basic settings
max_connections = 2048
thread_cache_size = 512
interactive_timeout = 30
wait_timeout = 30

# Query cache - useful for WordPress
query_cache_type = 1
query_cache_size = 32M
query_cache_limit = 256K

# InnoDB optimizations
innodb_file_per_table = 1
innodb_buffer_pool_instances = 1
innodb_open_files = 400
innodb_log_buffer_size = 32M 
innodb_lock_wait_timeout = 30
innodb_flush_log_at_trx_commit = 1     # Đảm bảo durability
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_method = O_DIRECT
innodb_io_capacity = 1000                   # SSD
innodb_io_capacity_max = 4000

# Table cache
table_open_cache = 2000
open_files_limit = 65535
tmp_table_size = 64M                       
max_heap_table_size = 64M                   

# Buffers
sort_buffer_size = 2M
read_buffer_size = 1M
read_rnd_buffer_size = 1M
join_buffer_size = 2M

# Network
max_allowed_packet = 64M

# Logging
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mariadb-slow.log
long_query_time = 2
log_queries_not_using_indexes = 1

# Performance Schema (optional)
performance_schema = ON 

# SQL Mode
sql_mode = STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,NO_AUTO_CREATE_USER

EOF

# Restart MariaDB to apply changes
systemctl restart mariadb

# ======== PHP-FPM CONFIGURATION ========

# Create PHP-FPM directory if it doesn't exist
echo -e "${BLUE}Creating PHP-FPM directories...${NC}"
mkdir -p "/etc/php/${php_version}/fpm/pool.d"

# Create PHP-FPM pool configuration exactly as the example
echo -e "${BLUE}Creating dedicated PHP-FPM pool for ${domain_name}...${NC}"
cat > "/etc/php/${php_version}/fpm/pool.d/pool_${domain_name}.conf" << EOF
[${domain_name}]
user = ${site_user}
group = ${site_user}
listen = /run/php/php${php_version}-fpm-${domain_name}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = static
pm.max_children = 20
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 6
EOF

# Create PHP conf.d directory if it doesn't exist
mkdir -p "/etc/php/${php_version}/fpm/conf.d"

# PHP optimization - create custom ini file with exact settings
echo -e "${BLUE}Optimizing PHP for WordPress...${NC}"
cat > "/etc/php/${php_version}/fpm/conf.d/99-custom.ini" << EOF

; --- Charset ---
default_charset = "UTF-8"

; Limits
max_execution_time = 3000
max_input_time = 6000
max_input_vars = 3000
post_max_size = 2048M
upload_max_filesize = 2048M
max_file_uploads = 200
memory_limit = 512M

; Opcache
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=1
opcache.revalidate_freq=60
opcache.save_comments=1
opcache.fast_shutdown=1
opcache.jit_buffer_size=64M
opcache.jit=tracing

; Cache
realpath_cache_size=4096k
realpath_cache_ttl=3600

; Security
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
disable_functions = passthru,system,proc_open,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_alarm,pcntl_waitpid,pcntl_wexitstatus,pcntl_wifexited,pcntl_wifsignaled,pcntl_wifstopped,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror

; Session
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.use_only_cookies = 1

EOF

# Restart PHP-FPM to apply changes
systemctl restart "php${php_version}-fpm"

# ======== NGINX CONFIGURATION ========

# Create main nginx.conf with fastcgi_cache_path in http context
echo -e "${BLUE}Setting up Nginx main configuration...${NC}"
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create mime.types if missing (critical)
if [ ! -f /etc/nginx/mime.types ]; then
  echo -e "${BLUE}Creating mime.types file...${NC}"
  curl -s https://raw.githubusercontent.com/nginx/nginx/master/conf/mime.types > /etc/nginx/mime.types
fi

# Create conf.d settings without SSL duplicates and without cache path
mkdir -p /etc/nginx/conf.d
echo -e "${BLUE}Creating 99-custom.conf in /etc/nginx/conf.d/...${NC}"
cat > /etc/nginx/conf.d/99-custom.conf << EOF
proxy_read_timeout 120s;
proxy_connect_timeout 120s;
proxy_buffer_size   128k;
proxy_buffers  4 256k;
proxy_busy_buffers_size 256k;

client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 5s;

keepalive_requests 100;

client_body_buffer_size 128k;

# Hide nginx version
server_tokens off;

# Open_file_cache
open_file_cache max=200000 inactive=20s;
open_file_cache_valid 30s;
open_file_cache_min_uses 2;
open_file_cache_errors on;

# FastCGI Cache settings - in HTTP context where it belongs
fastcgi_cache_path /var/run/nginx-cache levels=1:2 keys_zone=WORDPRESS:100m max_size=512m inactive=60m use_temp_path=off;
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
fastcgi_cache_lock on;
fastcgi_cache_use_stale error timeout invalid_header updating http_500 http_503;
fastcgi_keep_conn on;
fastcgi_cache_background_update on;

# Gzip Settings
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_buffers 16 8k;
gzip_http_version 1.1;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;


# SSL Settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

EOF

# Create snippets exactly as provided (except fcgi-caching.conf which needs fixing)
echo -e "${BLUE}Creating Nginx snippets...${NC}"
mkdir -p /etc/nginx/snippets

# FIXED FastCGI Caching snippet (without fastcgi_cache_path)
cat > /etc/nginx/snippets/fcgi-caching.conf << EOF
fastcgi_send_timeout 300s;
fastcgi_read_timeout 300s;
fastcgi_connect_timeout 300s;

# Increase the FastCGI buffer sizes
fastcgi_buffer_size 512k;
fastcgi_buffers 8 512k;
fastcgi_busy_buffers_size 512k;

# Hide PHP headers
fastcgi_hide_header X-Powered-By;
fastcgi_hide_header X-CF-Powered-By;
EOF

# GZIP
cat > /etc/nginx/snippets/gzip.conf << EOF
gzip on;
gzip_proxied expired no-cache no-store private auth;
gzip_types text/css text/xml application/javascript text/plain application/json image/svg+xml image/x-icon;
gzip_comp_level 6;
EOF

# Optimizer
cat > /etc/nginx/snippets/optimizer.conf << EOF
client_max_body_size 100M;
  
# allow the server to close connection on non responding client, this will free up memory
reset_timedout_connection on;

# request timed out -- default 60
client_body_timeout 10;

# if client stop responding, free up memory -- default 60
send_timeout 2;

# server will close connection after this time -- default 75
keepalive_timeout 60;

# number of requests client can make over keep-alive
keepalive_requests 100000;

sendfile on;
tcp_nopush on;
tcp_nodelay on;
EOF

# Rate Limiting
cat > /etc/nginx/snippets/rate-limiting.conf << EOF
# Rate limiting to protect against brute force
limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;
limit_req_status 429;
EOF

# WordPress Cache Skip
cat > /etc/nginx/snippets/wp-skip-cache.conf << EOF
# Set the variable "skip_cache" to 0 by default
set \$skip_cache 0;

# POST requests and urls with a query string should always go to PHP
if (\$query_string != "") {
  set \$skip_cache 1;
}

# Don't cache uris containing the following segments
if (\$request_uri ~* "(/wp-admin/|/xmlrpc.php|/wp-(app|cron|login|register|mail).php|wp-.*.php|/feed/|index.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(_index)?.xml|[a-z0-9_-]+-sitemap([0-9]+)?.xml)") {
  set \$skip_cache 1;
}

# Don't cache uris containing the following segments (woocommerce)
if (\$request_uri ~* "/store.*|/cart.*|/my-account.*|/checkout.*|/addons.*") {
  set \$skip_cache 1;
}

if ( \$arg_add-to-cart != "" ) {
  set \$skip_cache 1;
}

# Don't use the cache for logged in users or recent commenters
if (\$http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
  set \$skip_cache 1;
}

# Stop caching as soon as a visitor adds something to cart
if ( \$cookie_woocommerce_items_in_cart = "1" ) {
  set \$skip_cache 1;
}
EOF

# Create sites-available subdirectory if it doesn't exist
mkdir -p "$nginx_site_dir"

# Create NGINX server block with HTTP only first (for SSL validation)
echo -e "${BLUE}Creating initial HTTP-only Nginx configuration...${NC}"
cat > "$nginx_site_config" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain_name} www.${domain_name};
    
    # Allow Let's Encrypt verification
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root ${web_root};
    }
    
    # For initial setup, serve from web root
    location / {
        root ${web_root};
        index index.php index.html index.htm;
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
    
    # PHP configuration
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php${php_version}-fpm-${domain_name}.sock;
        fastcgi_index index.php;
    }
}
EOF

# Enable site configuration
echo -e "${BLUE}Enabling site configuration...${NC}"
mkdir -p /etc/nginx/sites-enabled
ln -sf "$nginx_site_config" "/etc/nginx/sites-enabled/${domain_name}.conf"

# Test and start Nginx with HTTP-only config
echo -e "${BLUE}Testing initial Nginx configuration...${NC}"
nginx -t
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Nginx configuration test passed!${NC}"
    systemctl restart nginx
else
    echo -e "${RED}Nginx configuration test failed. Please check error messages above.${NC}"
    exit 1
fi



# ======== SSL INSTALLATION WITH CERTBOT ========
echo -e "${BLUE}Installing SSL certificates with Certbot...${NC}"

# Đảm bảo port 80 mở
echo -e "${BLUE}Checking port 80 is open for SSL verification...${NC}"
if [ -x "$(command -v ufw)" ]; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi

# Tạm dừng Nginx để certbot có thể sử dụng port 80
systemctl stop nginx

# Tạo webroot directory
mkdir -p "$web_root/.well-known/acme-challenge"
chown -R www-data:www-data "$web_root/.well-known"
chmod -R 755 "$web_root/.well-known"

# Sử dụng phương pháp standalone thay vì webroot
echo -e "${BLUE}Obtaining SSL certificate for ${domain_name}...${NC}"
certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email "${ssl_email}" \
    --domains "${domain_name},www.${domain_name}" \
    --preferred-challenges http \
    --rsa-key-size 2048 \
    --force-renewal

# Kiểm tra kết quả cài đặt SSL
if [ $? -eq 0 ] && [ -d "/etc/letsencrypt/live/${domain_name}" ]; then
    echo -e "${GREEN}SSL certificate obtained successfully!${NC}"
    cert_path="/etc/letsencrypt/live/${domain_name}"
    using_lets_encrypt=true
    
    # Kiểm tra các file chứng chỉ
    echo -e "${BLUE}Verifying certificate files...${NC}"
    ls -la "$cert_path"
    
    # Kiểm tra quyền truy cập
    echo -e "${BLUE}Setting proper permissions for certificate files...${NC}"
    chmod -R 755 "/etc/letsencrypt/live"
    chmod -R 755 "/etc/letsencrypt/archive"
else
    echo -e "${RED}Failed to obtain Let's Encrypt certificate. Troubleshooting...${NC}"
    
    # Debug thêm
    echo -e "${YELLOW}Debug: Checking certbot logs...${NC}"
    tail -n 50 /var/log/letsencrypt/letsencrypt.log
    
    # Thử lại với tùy chọn debug
    echo -e "${BLUE}Trying again with debug options...${NC}"
    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "${ssl_email}" \
        --domains "${domain_name}" \
        --preferred-challenges http \
        --verbose
    
    # Kiểm tra lại sau khi thử lần 2
    if [ -d "/etc/letsencrypt/live/${domain_name}" ]; then
        echo -e "${GREEN}SSL certificate obtained on second attempt!${NC}"
        cert_path="/etc/letsencrypt/live/${domain_name}"
        using_lets_encrypt=true
    else
        echo -e "${RED}Still failed. Using temporary self-signed cert but will offer a fix...${NC}"
        mkdir -p "/etc/nginx/ssl/${domain_name}"
        openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
            -keyout "/etc/nginx/ssl/${domain_name}/privkey.pem" \
            -out "/etc/nginx/ssl/${domain_name}/fullchain.pem" \
            -subj "/CN=${domain_name}"
        cert_path="/etc/nginx/ssl/${domain_name}"
        using_lets_encrypt=false
    fi
fi

# Khởi động lại Nginx
systemctl start nginx

# Cài đặt cron job cho gia hạn tự động
if [ "$using_lets_encrypt" = true ]; then
    echo -e "${BLUE}Setting up automatic certificate renewal...${NC}"
    echo "0 3 * * * root certbot renew --quiet --pre-hook 'systemctl stop nginx' --post-hook 'systemctl start nginx'" > /etc/cron.d/certbot-renew
    chmod 644 /etc/cron.d/certbot-renew
fi



# Kiểm tra xem các file chứng chỉ có tồn tại không
if [ ! -f "${cert_path}/fullchain.pem" ] || [ ! -f "${cert_path}/privkey.pem" ]; then
    echo -e "${RED}SSL certificate files not found. Check paths: ${cert_path}/fullchain.pem and ${cert_path}/privkey.pem${NC}"
    echo -e "${YELLOW}Creating self-signed certificate as fallback...${NC}"
    mkdir -p "/etc/nginx/ssl/${domain_name}"
    openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
        -keyout "/etc/nginx/ssl/${domain_name}/privkey.pem" \
        -out "/etc/nginx/ssl/${domain_name}/fullchain.pem" \
        -subj "/CN=${domain_name}/O=WordPress Installation/C=VN"
    cert_path="/etc/nginx/ssl/${domain_name}"
    using_lets_encrypt=false
fi


# Now update Nginx configuration with HTTPS
echo -e "${BLUE}Updating Nginx configuration with HTTPS...${NC}"
cat > "$nginx_site_config" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain_name} www.${domain_name};
    
    # Allow Let's Encrypt verification before redirect
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root ${web_root};
    }
    
    # Redirect all HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    charset utf-8;
    server_name ${domain_name} www.${domain_name};
    root ${web_root};
    
    # Standard HTTPS listening
    listen 443 ssl;
    http2 on;
    listen 443 quic reuseport;
    http3 on;
    
    # SSL Configuration
    ssl_certificate ${cert_path}/fullchain.pem;
    ssl_certificate_key ${cert_path}/privkey.pem;
    
    # SSL Settings
    ssl_protocols TLSv1.3;
    ssl_early_data on;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519:P-256:P-384:P-521;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # Auto index
    index index.php index.html index.htm;
    
    # Include snippets
    include snippets/optimizer.conf;
    include snippets/gzip.conf;
    include snippets/wp-skip-cache.conf;

    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php${php_version}-fpm-${domain_name}.sock;
        fastcgi_index index.php;

        # FastCGI caching 
        include snippets/fcgi-caching.conf;

        # Đảm bảo header Alt-Svc được gửi từ PHP scripts
        add_header Alt-Svc 'h3=":443"; ma=86400' always;

        # X-FastCGI-Cache
        add_header X-FastCGI-Cache \$upstream_cache_status;
    }
    
    location ~* ^.+\.(jpg|jpeg|gif|png|svg|js|css|mp3|ogg|mpeg|avi|zip|gz|bz2|rar|swf|ico|7z|doc|docx|map|ogg|otf|pdf|tff|tif|txt|wav|webp|woff|woff2|xls|xlsx|xml|ttf|avif)$ {
        try_files \$uri \$uri/ @fallback;
        expires 30d;
        access_log off;
        add_header Cache-Control "public, max-age=2592000";
    }
    
    #deny access to .htaccess files
    location ~ /\.ht {
        deny all;
    }
    
    # deny access to .git
    location ~ /\.git {
        access_log off;
        log_not_found off;
        return 404;
    }
    
    # Hiding all hidden nodes except .well-known which is used by ACME
    location ~ /\.(?!well-known).* {
        access_log off;
        log_not_found off;
        return 404;
    }
    
    # Log settings
    access_log ${logs_dir}/${domain_name}.access.log;
    error_log ${logs_dir}/${domain_name}.error.log;
}
EOF

# Test and restart Nginx with HTTPS config
echo -e "${BLUE}Testing updated Nginx configuration with SSL...${NC}"
nginx -t
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Nginx configuration with SSL test passed!${NC}"
    systemctl restart nginx
else
    echo -e "${RED}Nginx configuration test failed. Attempting to fix...${NC}"
    # Fix common issues in configuration
    sed -i "s|ssl_certificate .*|ssl_certificate ${cert_path}/fullchain.pem;|" "$nginx_site_config"
    sed -i "s|ssl_certificate_key .*|ssl_certificate_key ${cert_path}/privkey.pem;|" "$nginx_site_config"
    
    # Test again
    nginx -t && systemctl restart nginx
    if [ $? -ne 0 ]; then
        echo -e "${RED}Could not fix Nginx configuration. Manual intervention required.${NC}"
        exit 1
    fi
fi

# ======== DOWNLOAD AND INSTALL WORDPRESS ========

if [[ "$install_wordpress" == "y" || "$install_wordpress" == "Y" ]]; then
  echo -e "${BLUE}Downloading and installing WordPress...${NC}"
  
  # Check if WordPress is already installed
  if [ -f "$web_root/wp-config.php" ]; then
    read -p "WordPress appears to be already installed. Reinstall? (y/n) [n]: " reinstall_wp
    if [[ "$reinstall_wp" != "y" && "$reinstall_wp" != "Y" ]]; then
      echo -e "${YELLOW}Skipping WordPress installation.${NC}"
    else

      # Backup existing WordPress files
      # echo -e "${BLUE}Backing up existing WordPress installation...${NC}"
      # backup_dir="/var/www/backups/${domain_name}_$(date +%Y%m%d%H%M%S)"
      # mkdir -p "$backup_dir"
      # cp -a "$web_root/." "$backup_dir/"
      
      # Download and install WordPress
      cd /tmp
      curl -LO https://wordpress.org/latest.tar.gz
      tar -xzf latest.tar.gz
      cp -a /tmp/wordpress/. "$web_root"
      
      # Rest of WordPress installation...
    fi
  else
    # Fresh WordPress installation
    cd /tmp
    curl -LO https://wordpress.org/latest.tar.gz
    tar -xzf latest.tar.gz
    cp -a /tmp/wordpress/. "$web_root"
    
    # Rest of WordPress installation...
  fi
fi

# Create wp-config.php
echo -e "${BLUE}Creating WordPress configuration...${NC}"
cp "$web_root/wp-config-sample.php" "$web_root/wp-config.php"
sed -i "s/database_name_here/$db_name/" "$web_root/wp-config.php"
sed -i "s/username_here/$db_user/" "$web_root/wp-config.php"
sed -i "s/password_here/$db_password/" "$web_root/wp-config.php"


# Add security salts
wp_salt_line_number=$(grep -n "'AUTH_KEY'" "$web_root/wp-config.php" | cut -d: -f1)
sed -i '/_KEY/d;/_SALT/d' "$web_root/wp-config.php"
new_salts=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
sed -i "${wp_salt_line_number}r /dev/stdin" "$web_root/wp-config.php" <<< "$new_salts"

# Add additional security configurations to wp-config.php
cat >> "$web_root/wp-config.php" << EOF

/* Additional security settings */
# define('DISALLOW_FILE_EDIT', true);
define('WP_POST_REVISIONS', 5);
define('WP_MEMORY_LIMIT', '512M');
define('WP_MAX_MEMORY_LIMIT', '512M');
EOF

# ======== PERMISSIONS ========

echo -e "${BLUE}Setting proper permissions...${NC}"
# Set ownership
chown -R "$site_user:$site_user" "/var/www/${site_user}"

# Add www-data to the site user group to allow NGINX to access files
usermod -a -G "$site_user" www-data

# Set directory and file permissions with more restrictive approach
find "$web_root" -type d -exec chmod 750 {} \;
find "$web_root" -type f -exec chmod 640 {} \;

# Make wp-content writable but more secure
mkdir -p "$web_root/wp-content/uploads"
chmod -R 770 "$web_root/wp-content"
chown -R "$site_user:www-data" "$web_root/wp-content"

# Set directory inheritance so new files get correct group
find "$web_root" -type d -exec chmod g+s {} \;

# Protect sensitive files
if [ -f "$web_root/wp-config.php" ]; then
  chmod 600 "$web_root/wp-config.php"
  chown "$site_user:$site_user" "$web_root/wp-config.php"
fi

# ======== FINAL STEPS ========

# Restart services
systemctl restart "php${php_version}-fpm"
systemctl restart nginx
systemctl restart mariadb

# Performing final database check
echo -e "${BLUE}Performing final database check...${NC}"
if ! mysql -u "$db_user" -p"$db_password" -e "USE ${db_name}; SELECT 1;" >/dev/null 2>&1; then
  echo -e "${RED}Warning: Database connection still not working with WordPress user.${NC}"
  echo -e "${YELLOW}Running additional fix...${NC}"
  
  # Fix cuối cùng - đảm bảo chắc chắn quyền được thiết lập
  mysql -u root -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost' IDENTIFIED BY '${db_password}';"
  mysql -u root -e "FLUSH PRIVILEGES;"
else
  echo -e "${GREEN}Database connection verified successfully!${NC}"
fi

# Verify HTTPS is working
echo -e "${BLUE}Verifying HTTPS is properly configured...${NC}"
sleep 5
if curl -s -I "https://${domain_name}" | grep -q "200 OK"; then
    echo -e "${GREEN}HTTPS is working properly!${NC}"
else
    echo -e "${YELLOW}HTTPS might not be fully configured yet. Please check the server and DNS settings.${NC}"
fi

# ======== INSTALLATION COMPLETE ========

echo -e "${GREEN}═════════════════════════════════════════════════${NC}"
echo -e "${GREEN}    WordPress Installation Complete!              ${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Website URL:${NC} https://${domain_name}"
echo -e "${BLUE}WordPress Admin:${NC} https://${domain_name}/wp-admin/"
echo
echo -e "${BLUE}Database Information:${NC}"
echo -e "  Database Name: ${YELLOW}${db_name}${NC}"
echo -e "  Database User: ${YELLOW}${db_user}${NC}"
echo -e "  Database Password: ${YELLOW}${db_password}${NC}"
echo
echo -e "${BLUE}Installation Details:${NC}"
echo -e "  Web Root: ${YELLOW}${web_root}${NC}"
echo -e "  PHP Version: ${YELLOW}${php_version}${NC}"
echo -e "  MariaDB Version: ${YELLOW}${mariadb_version}${NC}"
echo -e "  Site User: ${YELLOW}${site_user}${NC}"
echo -e "  Nginx Config: ${YELLOW}${nginx_site_config}${NC}"
echo
echo -e "${BLUE}Complete the WordPress installation by visiting:${NC}"
echo -e "${GREEN}https://${domain_name}${NC}"
echo
echo -e "${YELLOW}IMPORTANT: Save this information for your records!${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════${NC}"

# Save this information to a file
cat > "/root/.wp-install-${domain_name}.txt" << EOF
WordPress Installation Information
=============================================
Date: $(date)
Website URL: https://${domain_name}
WordPress Admin: https://${domain_name}/wp-admin/

Database Information:
  Database Name: ${db_name}
  Database User: ${db_user}
  Database Password: ${db_password}

Installation Details:
  Web Root: ${web_root}
  PHP Version: ${php_version}
  MariaDB Version: ${mariadb_version}
  Site User: ${site_user}
  Nginx Config: ${nginx_site_config}
=============================================
EOF

chmod 600 "/root/.wp-install-${domain_name}.txt"
echo -e "${GREEN}Installation details saved to /root/.wp-install-${domain_name}.txt${NC}"