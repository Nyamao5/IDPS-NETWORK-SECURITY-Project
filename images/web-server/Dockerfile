FROM debian:bullseye-slim

# Install only absolute minimum packages needed (no recommendations)
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    php-cli \
    libapache2-mod-php \
    vsftpd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure vulnerable web application (minimal setup)
COPY ./app/ /var/www/html/
RUN chmod -R 755 /var/www/html/

# Configure FTP server (minimal setup)
COPY vsftpd.conf /etc/vsftpd.conf
RUN mkdir -p /var/run/vsftpd/empty /var/ftp \
    && useradd -m ftpuser \
    && echo "ftpuser:password" | chpasswd

# Expose only essential ports
EXPOSE 80 21 20

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]