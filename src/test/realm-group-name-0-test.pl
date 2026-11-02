#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::OpenId;
use PVE::Auth::LDAP;
use PVE::RPCEnvironment;

# Groups named '0' coming from an OpenID Connect claim or an LDAP directory are valid and must not
# be dropped.

my $user_cfg_raw = "user:alice\@oidc:1:\n\ngroup:0-oidc:::\ngroup:normal-oidc:::\n";
my @syslog;

my $domains_cfg = {
    ids => {
        oidc => {
            type => 'openid',
            'issuer-url' => 'https://oidc.invalid',
            'client-id' => 'test',
            'groups-claim' => 'groups',
            'groups-overwrite' => 1,
        },
    },
};

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(
    lock_user_config => sub { $_[0]->() },
    assemble_ticket => sub { 'ticket' },
    assemble_csrf_prevention_token => sub { 'csrf' },
);

my $openid_api_module = Test::MockModule->new('PVE::API2::OpenId');
$openid_api_module->mock(
    cfs_read_file => sub($file) {
        return $domains_cfg if $file eq 'domains.cfg';
        return PVE::AccessControl::parse_user_config($file, $user_cfg_raw)
            if $file eq 'user.cfg';
        die "unexpected cfs_read_file('$file') call\n";
    },
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg_raw = PVE::AccessControl::write_user_config($file, $cfg);
    },
    syslog => sub { push @syslog, $_[1] },
);

my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'datacenter.cfg';
        return {};
    },
    get_clinfo => sub { {} },
    log_msg => sub { },
);

my $openid_rs_module = Test::MockModule->new('PVE::RS::OpenId');
$openid_rs_module->mock(
    verify_public_auth_state => sub { ('oidc', {}) },
    discover => sub { bless {}, 'TestOpenIdClient' },
);

package TestOpenIdClient {
    sub verify_authorization_code { return { sub => 'alice', groups => ['0', 'normal'] } }
}

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->{user_cfg} = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);

PVE::API2::OpenId->login(
    { state => 'state', code => 'code', 'redirect-url' => 'https://pve.invalid' });
my $cfg = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);
is(
    join(',', sort keys $cfg->{users}->{'alice@oidc'}->{groups}->%*),
    '0-oidc,normal-oidc',
    "OpenID Connect login keeps a group named '0'",
);
ok(!grep({ /invalid characters/ } @syslog), 'no group got rejected') or diag(@syslog);

my $ldap_plugin_module = Test::MockModule->new('PVE::Auth::LDAP');
$ldap_plugin_module->mock(connect_and_bind => sub { return {} });

my $ldap_module = Test::MockModule->new('PVE::LDAP');
$ldap_module->mock(
    query_groups => sub {
        return [
            { name => '0', dn => 'cn=0,dc=example', members => ['uid=alice,dc=example'] },
            { name => 'normal', dn => 'cn=normal,dc=example', members => [] },
        ];
    },
);

my $groups = PVE::Auth::LDAP->get_groups({}, 'ldap', { 'uid=alice,dc=example' => 'alice@ldap' });
is(join(',', sort keys %$groups), '0-ldap,normal-ldap', "LDAP sync keeps a group named '0'");
is_deeply($groups->{'0-ldap'}->{users}, { 'alice@ldap' => 1 }, "group '0' keeps its members");

$ldap_module->mock(
    query_groups => sub {
        return [{ dn => 'cn=0,dc=example', members => [] }];
    },
);
$groups = PVE::Auth::LDAP->get_groups({}, 'ldap', {});
is(join(',', sort keys %$groups), '0-ldap', "LDAP sync takes a group name '0' from the DN");

done_testing();
