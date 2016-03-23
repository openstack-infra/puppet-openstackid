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
  $git_source_repo = 'https://git.openstack.org/openstack-infra/openstackid',
  $site_admin_password = '',
  $id_mysql_host = '',
  $id_mysql_user = '',
  $id_mysql_password = '',
  $id_db_name = '',
  $ss_mysql_host = '',
  $ss_mysql_user = '',
  $ss_mysql_password = '',
  $ss_db_name = '',
  $redis_port = '',
  $redis_host = '',
  $redis_password = '',
  $vhost_name = $::fqdn,
  $robots_txt_source = '',
  $serveradmin = "webmaster@${::fqdn}",
  $canonicalweburl = "https://${::fqdn}/",
  $ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem',
  $ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key',
  $ssl_chain_file = '',
  $ssl_cert_file_contents = '', # If left empty puppet will not create file.
  $ssl_key_file_contents = '', # If left empty puppet will not create file.
  $ssl_chain_file_contents = '', # If left empty puppet will not create file.
  $httpd_acceptorthreads = '',
  $id_log_error_to_email = '',
  $id_log_error_from_email = '',
  $id_environment = 'dev',
  $id_hostname = $::hostname,
  $id_recaptcha_public_key = '',
  $id_recaptcha_private_key = '',
  $id_recaptcha_template = '',
  $openstackid_release = 'latest',
  $ssl_enable = true,
  $oauth2_enable = true,
  $app_url = '',
  $app_key = '',
  $app_version = '',
  $app_timezone = 'UTC',
  $email_driver = 'mail',
  $email_smtp_server = 'smtp.mailgun.org',
  $email_smtp_server_port = 587,
  $email_smtp_server_user = '',
  $email_smtp_server_password = '',
  $use_db_seeding = false,
) {

  # php packages needed for openid server
  $php5_packages = [
      'php5-common',
      'php5-curl',
      'php5-cli',
      'php5-mcrypt',
      'php5-mysql',
    ]

  package { $php5_packages:
    ensure => present,
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

  include ::httpd
  include ::httpd::ssl
  include ::httpd::php
  ::httpd::vhost { $vhost_name:
    port     => 443,
    docroot  => '/srv/openstackid/w/public',
    priority => '50',
    template => 'openstackid/vhost.erb',
    ssl      => true,
    require  => File[$docroot_dirs],
  }
  httpd_mod { 'rewrite':
    ensure => present,
  }
  httpd_mod { 'proxy':
    ensure => present,
  }
  httpd_mod { 'proxy_http':
    ensure => present,
  }

  if $ssl_cert_file_contents != '' {
    file { $ssl_cert_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_cert_file_contents,
      notify  => Service['apache2'],
      before  => Httpd::Vhost[$vhost_name],
    }
  }

  if $ssl_key_file_contents != '' {
    file { $ssl_key_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_key_file_contents,
      notify  => Service['apache2'],
      before  => Httpd::Vhost[$vhost_name],
    }
  }

  if $ssl_chain_file_contents != '' {
    file { $ssl_chain_file:
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => $ssl_chain_file_contents,
      notify  => Service['apache2'],
      before  => Httpd::Vhost[$vhost_name],
    }
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
      Httpd::Vhost[$vhost_name],
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
      Httpd::Vhost[$vhost_name],
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

}
