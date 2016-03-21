# Copyright 2013  OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# openstackid idp(sso-openid)
#
# == Class: openstackid
#
class openstackid (
  $app_key                    = '',
  $app_timezone               = 'UTC',
  $app_url                    = '',
  $app_version                = '',
  $canonicalweburl            = "https://${::fqdn}/",
  $docroot                    = '/srv/openstackid/w/public',
  $email_driver               = 'mail',
  $email_smtp_server          = 'smtp.mailgun.org',
  $email_smtp_server_password = '',
  $email_smtp_server_port     = 587,
  $email_smtp_server_user     = '',
  $git_source_repo            = 'https://git.openstack.org/openstack-infra/openstackid',
  $httpd_acceptorthreads      = '',
  $id_db_name                 = '',
  $id_environment             = 'dev',
  $id_hostname                = $::fqdn,
  $id_mysql_host              = '',
  $id_mysql_password          = '',
  $id_mysql_user              = '',
  $id_log_error_from_email    = '',
  $id_log_error_to_email      = '',
  $id_recaptcha_private_key   = '',
  $id_recaptcha_public_key    = '',
  $id_recaptcha_template      = '',
  $oauth2_enable              = true,
  $openstackid_release        = 'latest',
  $redis_host                 = '',
  $redis_password             = '',
  $redis_port                 = '',
  $robots_txt_source          = '',
  $serveradmin                = "webmaster@${::fqdn}",
  $site_admin_password        = '',
  $ss_db_name                 = '',
  $ss_mysql_host              = '',
  $ss_mysql_password          = '',
  $ss_mysql_user              = '',
  $ssl_enable                 = true,
  $ssl_cert_file              = '/etc/ssl/certs/ssl-cert-snakeoil.pem',
  $ssl_cert_file_contents     = '', # If left empty puppet will not create file.
  $ssl_chain_file             = '',
  $ssl_chain_file_contents    = '', # If left empty puppet will not create file.
  $ssl_key_file               = '/etc/ssl/private/ssl-cert-snakeoil.key',
  $ssl_key_file_contents      = '', # If left empty puppet will not create file.
  $use_db_seeding             = false,
  $vhost_name                 = $::fqdn,
  $use_db_seeding             = false,
) {

  # php packages needed for openid server
  $php5_packages = [
      'php5-common',
      'php5-curl',
      'php5-cli',
      'php5-mcrypt',
      'php5-mysqlnd',
      'php5-fpm',
      'php5-json',
      'php5-gmp',
    ]

  package { $php5_packages:
    ensure => present,
  }

  # php5-fpm configuration

  exec { 'enable_php5-mbcrypt':
    command => '/usr/sbin/php5enmod mcrypt',
    timeout => 0,
    require => [
      Package['php5-fpm'],
    ],
    notify  => Service['php5-fpm'],
  }

  file { '/etc/php5/fpm/pool.d/www.conf':
    ensure  => present,
    owner   => 'root',
    group   => 'www-data',
    mode    => '0640',
    source  => 'puppet:///modules/openstackid/www.conf',
    require => [
      Package['php5-fpm'],
    ],
    notify  => Service['php5-fpm'],
  }

  service { 'php5-fpm':
    ensure  => 'running',
    enable  => true,
    require => Package['php5-fpm'],
  }

  # the deploy scripts use the curl CLI
  package { 'curl':
    ensure => present,
  }

  # install nodejs default version
  class { '::nodejs':
  }

  group { 'openstackid':
    ensure => present,
  }

  user { 'openstackid':
    ensure     => present,
    managehome => true,
    comment    => 'OpenStackID User',
    shell      => '/bin/bash',
    gid        => 'openstackid',
    require    => Group['openstackid'],
  }

  file { '/etc/openstackid':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/etc/openstackid/database.php':
    ensure  => present,
    content => template('openstackid/database.php.erb'),
    owner   => 'root',
    group   => 'www-data',
    mode    => '0640',
    require => [
      File['/etc/openstackid'],
    ]
  }

  file { '/etc/openstackid/app.php':
    ensure  => present,
    content => template('openstackid/app.php.erb'),
    owner   => 'root',
    group   => 'www-data',
    mode    => '0640',
    require => [
      File['/etc/openstackid'],
    ]
  }

  file { '/etc/openstackid/log.php':
      ensure  => present,
      content => template('openstackid/log.php.erb'),
      owner   => 'root',
      group   => 'www-data',
      mode    => '0640',
      require => [
        File['/etc/openstackid'],
      ]
  }

  file { '/etc/openstackid/environment.php':
      ensure  => present,
      content => template('openstackid/environment.php.erb'),
      owner   => 'root',
      group   => 'www-data',
      mode    => '0640',
      require => [
        File['/etc/openstackid'],
      ]
  }

  file { '/etc/openstackid/recaptcha.php':
        ensure  => present,
        content => template('openstackid/recaptcha.php.erb'),
        owner   => 'root',
        group   => 'www-data',
        mode    => '0640',
        require => [
          File['/etc/openstackid'],
        ]
  }

  file { '/etc/openstackid/server.php':
        ensure  => present,
        content => template('openstackid/server.php.erb'),
        owner   => 'root',
        group   => 'www-data',
        mode    => '0640',
        require => [
          File['/etc/openstackid'],
        ]
  }

  file { '/etc/openstackid/mail.php':
    ensure  => present,
    content => template('openstackid/mail.php.erb'),
    owner   => 'root',
    group   => 'www-data',
    mode    => '0640',
    require => [
      File['/etc/openstackid'],
    ]
  }

  $docroot_dirs = [ '/srv/openstackid' ]

  file { $docroot_dirs:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  class { '::apache':
    default_vhost => false,
    mpm_module    => false,
  }

  # apache mpm event connectio tweaking
  class {'::apache::mod::event':
    serverlimit         => 128,
    startservers        => 3,
    minsparethreads     => 96,
    maxsparethreads     => 192,
    threadlimit         => 64,
    threadsperchild     => 32,
    maxclients          => 4096,
    maxrequestsperchild => 5000,
    maxrequestworkers   => 4096,
  }

  ::apache::listen { '80': }
  ::apache::listen { '443': }

  ::apache::vhost::custom { $vhost_name:
    priority => '50',
    content  => template('openstackid/vhost.erb'),
    require  => File[$docroot_dirs],
  }

  class { '::apache::mod::ssl': }
  class { '::apache::mod::rewrite': }
  class { '::apache::mod::proxy': }

  if ($::lsbdistcodename == 'precise') {
    class { '::apache::mod::fastcgi': }
    class { '::apache::mod::actions': }
  }
  else {
    ::apache::mod { 'proxy_fcgi': }
  }

  if $ssl_cert_file_contents != '' {
    file { $ssl_cert_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_cert_file_contents,
      notify  => Class['::apache::service'],
      before  => Apache::Vhost::Custom[$vhost_name],
    }
  }

  if $ssl_key_file_contents != '' {
    file { $ssl_key_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_key_file_contents,
      notify  => Class['::apache::service'],
      before  => Apache::Vhost::Custom[$vhost_name],
    }
  }

  if $ssl_chain_file_contents != '' {
    file { $ssl_chain_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_chain_file_contents,
      notify  => Class['::apache::service'],
      before  => Apache::Vhost::Custom[$vhost_name],
    }
  }

  file { '/etc/apache2':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  deploy { 'deploytool':
  }

  file { '/opt/deploy/conf.d/openstackid.conf':
    content => template('openstackid/openstackid.conf.erb'),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Deploy['deploytool'],
  }

  exec { 'deploy-site':
    path      => '/usr/local/bin:/usr/bin:/bin',
    command   => '/opt/deploy/deploy.sh init openstackid',
    onlyif    => '/opt/deploy/deploy.sh status openstackid | grep N/A',
    logoutput => on_failure,
    require   => [
      File['/opt/deploy/conf.d/openstackid.conf'],
      Apache::Vhost::Custom[$vhost_name],
      File['/etc/openstackid/recaptcha.php'],
      File['/etc/openstackid/database.php'],
      File['/etc/openstackid/log.php'],
      File['/etc/openstackid/environment.php'],
      File['/etc/openstackid/server.php'],
      File['/etc/openstackid/app.php'],
      Package['curl'],
      Package[$php5_packages] ,
      Class['::nodejs'],
    ],
  }

  exec { 'update-site':
    path      => '/usr/local/bin:/usr/bin:/bin',
    command   => '/opt/deploy/deploy.sh update openstackid',
    onlyif    => '/opt/deploy/deploy.sh status openstackid | grep UPDATE',
    logoutput => on_failure,
    require   => [
      File['/opt/deploy/conf.d/openstackid.conf'],
      Apache::Vhost::Custom[$vhost_name],
      File['/etc/openstackid/recaptcha.php'],
      File['/etc/openstackid/database.php'],
      File['/etc/openstackid/app.php'],
      File['/etc/openstackid/log.php'],
      File['/etc/openstackid/environment.php'],
      File['/etc/openstackid/server.php'],
      Package[$php5_packages] ,
      Class['::nodejs'],
    ],
  }

  # system configuration tweaking
  $my_sysctl_settings = {
    # redis : http://redis.io/topics/admin
    'vm.overcommit_memory'        => { value => 1 },
    'net.core.rmem_default'       => { value => 31457280 },
    'net.core.rmem_max'           => { value => 12582912 },
    'net.core.wmem_default'       => { value => 31457280 },
    'net.core.wmem_max'           => { value => 12582912 },
    # Increase number of incoming connections
    'net.core.somaxconn'          => { value => 4096 },
    # Increase number of incoming connections backlog
    'net.core.netdev_max_backlog' => { value => 65536 },
    'net.core.optmem_max'         => { value => 25165824 },
    'net.ipv4.tcp_mem'            => { value => "65536\t131072\t262144" },
    'net.ipv4.udp_mem'            => { value => "65536\t131072\t262144" },
    'net.ipv4.tcp_rmem'           => { value => "8192\t87380\t16777216" },
    'net.ipv4.udp_rmem_min'       => { value => 16384 },
    'net.ipv4.tcp_wmem'           => { value => "8192\t65536\t16777216" },
    'net.ipv4.udp_wmem_min'       => { value => 16384 },
    'net.ipv4.tcp_max_tw_buckets' => { value => 1440000 },
    # Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
    'net.ipv4.tcp_tw_recycle'     => { value => 1 },
    'net.ipv4.tcp_tw_reuse'       => { value => 1 },
  }

  $my_sysctl_defaults = {
  }

  create_resources(sysctl::value,$my_sysctl_settings,$my_sysctl_defaults)

}
