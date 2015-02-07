#!/bin/bash

# Exit the script if one of the commands fails
set -e

# Directory where entire Django application is located
APPLICATION_DIR="/vagrant"

# Default external configuration files
CELERY_CONFIGS_DIR="$APPLICATION_DIR/RAPID/external_configs/celery"
APACHE_CONFIGS_DIR="$APPLICATION_DIR/RAPID/external_configs/apache2"

# Update package list and upgrade all packages
apt-get update
apt-get -y upgrade

# Install dependency packages for application
apt-get install -y whois
apt-get install -y rabbitmq-server
apt-get install -y python3-all-dev
apt-get install -y python3-pip
apt-get install -y libpq-dev
echo "Prerequisites installed"

cd $APPLICATION_DIR
pip3 install -r requirements.txt
echo "Python package requirements installed"

# Install Apache
apt-get install -y apache2
apt-get install -y libapache2-mod-wsgi-py3
echo "Apache installed"

# Install Postgres
apt-get install -y postgresql postgresql-contrib
echo "Postgres installed"