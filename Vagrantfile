# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # Base Box for Virtual Environment Setup
  config.vm.box = "ubuntu/trusty64"

  # Provisioning Script for initial setup and dependencies
  config.vm.provision :shell, path: "bootstrap.sh"

  # Forward port mapping for Django development, HTTPS, and HTTP
  config.vm.network "forwarded_port", guest: 8000, host: 8000

end

