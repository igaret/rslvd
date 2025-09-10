#!/bin/bash

# Production RSLVD DNS Installation Script

set -e

# Configuration
INSTALL_DIR="/opt/rslvd"
CONFIG_DIR="/etc/rslvd"
LOG_DIR="/var/log/rslvd"
USER="dns"
GROUP="dns"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
   
    log_info "Detected OS: $OS $VER"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
   
    case $OS in
        "Ubuntu"*)
            apt-get update
            apt-get install -y build-essential cmake libssl-dev pkg-config
            ;;
        "CentOS"*|"Red Hat"*)
            yum groupinstall -y "Development Tools"
            yum install -y cmake openssl-devel pkgconfig
            ;;
        "Fedora"*)
            dnf groupinstall -y "Development Tools"
            dnf install -y cmake openssl-devel pkgconfig
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Create user and directories
create_user_and_dirs() {
    log_info "Creating user and directories..."
   
    # Create user
    if ! id "$USER" &>/dev/null; then
        useradd -r -s /bin/false -d $INSTALL_DIR $USER
        log_info "Created user: $USER"
    fi
   
    # Create directories
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR/{zones,keys}
    mkdir -p $LOG_DIR
   
    # Set permissions
    chown -R $USER:$GROUP $INSTALL_DIR
    chown -R $USER:$GROUP $CONFIG_DIR
    chown -R $USER:$GROUP $LOG_DIR
   
    chmod 755 $INSTALL_DIR
    chmod 750 $CONFIG_DIR
    chmod 750 $LOG_DIR
    chmod 700 $CONFIG_DIR/keys
}

# Build and install
build_and_install() {
    log_info "Building RSLVD DNS..."
   
    # Create build directory
    mkdir -p build
    cd build
   
    # Configure and build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR
    make -j$(nproc)
   
    # Install
    make install
   
    log_info "RSLVD DNS built and installed"
}

# Install configuration files
install_config() {
    log_info "Installing configuration files..."
   
    # Copy configuration files
    cp config/rslvd.conf $CONFIG_DIR/
    cp config/acl.conf $CONFIG_DIR/
   
    # Create sample zone file
    cat > $CONFIG_DIR/zones/example.com.zone << 'EOF'
; Example zone file
$ORIGIN example.com.
$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. (
                2024010101  ; Serial
                3600        ; Refresh
                1800        ; Retry
                604800      ; Expire
                86400       ; Minimum TTL
                )

@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.
@       IN  A   192.0.2.1
www     IN  A   192.0.2.2
EOF
   
    # Set permissions
    chown -R $USER:$GROUP $CONFIG_DIR
    chmod 640 $CONFIG_DIR/*.conf
    chmod 644 $CONFIG_DIR/zones/*.zone
   
    log_info "Configuration files installed"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
   
    cat > /etc/systemd/system/rslvd.service << EOF
[Unit]
Description=Production RSLVD DNS
After=network.target
Documentation=https://github.com/your-org/production-rslvd

[Service]
Type=forking
User=$USER
Group=$GROUP
ExecStart=$INSTALL_DIR/bin/rslvd -d -c $CONFIG_DIR/rslvd.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $CONFIG_DIR/zones

[Install]
WantedBy=multi-user.target
EOF
   
    # Reload systemd
    systemctl daemon-reload
    systemctl enable rslvd
   
    log_info "Systemd service installed and enabled"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
   
    if command -v ufw &> /dev/null; then
        ufw allow 53/udp
        ufw allow 53/tcp
        ufw allow 8080/tcp  # Metrics port
        log_info "UFW rules added"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --reload
        log_info "Firewalld rules added"
    else
        log_warn "No supported firewall found. Please configure manually."
    fi
}

# Post-installation setup
post_install() {
    log_info "Performing post-installation setup..."
   
    # Create log rotation configuration
    cat > /etc/logrotate.d/rslvd << EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $USER $GROUP
    postrotate
        systemctl reload rslvd
    endscript
}
EOF
   
    # Set up monitoring (if Prometheus is available)
    if command -v prometheus &> /dev/null; then
        log_info "Prometheus detected. Consider adding RSLVD DNS to scrape config."
    fi
   
    log_info "Post-installation setup complete"
}

# Main installation function
main() {
    log_info "Starting RSLVD DNS installation..."
   
    check_root
    detect_os
    install_dependencies
    create_user_and_dirs
    build_and_install
    install_config
    install_systemd_service
    configure_firewall
    post_install
   
    log_info "Installation completed successfully!"
    echo
    log_info "Next steps:"
    echo "1. Edit configuration: $CONFIG_DIR/rslvd.conf"
    echo "2. Add your zone files to: $CONFIG_DIR/zones/"
    echo "3. Start the service: systemctl start rslvd"
    echo "4. Check status: systemctl status rslvd"
    echo "5. View logs: journalctl -u rslvd -f"
    echo "6. Test DNS: dig @localhost example.com"
}

# Run main function
main "$@"
