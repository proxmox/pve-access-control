package PVE::API2::Jobs::RealmSync;

use strict;
use warnings;

use PVE::Cluster qw(cfs_lock_file cfs_read_file cfs_write_file);
use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Job::Registry ();
use PVE::SectionConfig ();
use PVE::Tools qw(extract_param);

use PVE::Jobs::RealmSync ();

use base qw(PVE::RESTHandler);

my $get_cluster_last_run = sub {
    my ($jobid) = @_;

    my $state = eval { PVE::Jobs::RealmSync::get_state($jobid) };
    die "error on getting state for '$jobid': $@\n" if $@;

    if (my $upid = $state->{upid}) {
        if (my $decoded = PVE::Tools::upid_decode($upid)) {
            return $decoded->{starttime};
        }
    } else {
        return $state->{time};
    }

    return undef;
};

__PACKAGE__->register_method({
    name => 'syncjob_index',
    path => '',
    method => 'GET',
    description => "List configured realm-sync-jobs.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {
                id => {
                    description => "The ID of the entry.",
                    type => 'string',
                },
                enabled => {
                    description => "If the job is enabled or not.",
                    type => 'boolean',
                },
                comment => {
                    description => "A comment for the job.",
                    type => 'string',
                    optional => 1,
                },
                schedule => {
                    description => "The configured sync schedule.",
                    type => 'string',
                },
                realm => get_standard_option('realm'),
                scope => get_standard_option('sync-scope'),
                'remove-vanished' => get_standard_option('sync-remove-vanished'),
                'last-run' => {
                    description =>
                        "Last execution time of the job in seconds since the beginning of the UNIX epoch",
                    type => 'integer',
                    optional => 1,
                },
                'next-run' => {
                    description =>
                        "Next planned execution time of the job in seconds since the beginning of the UNIX epoch.",
                    type => 'integer',
                    optional => 1,
                },
            },
        },
        links => [{ rel => 'child', href => "{id}" }],
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $user = $rpcenv->get_user();

        my $jobs_data = cfs_read_file('jobs.cfg');
        my $order = $jobs_data->{order};
        my $jobs = $jobs_data->{ids};

        my $res = [];
        for my $jobid (sort { $order->{$a} <=> $order->{$b} } keys %$jobs) {
            my $job = $jobs->{$jobid};
            next if $job->{type} ne 'realm-sync';

            $job->{id} = $jobid;
            if (my $schedule = $job->{schedule}) {
                $job->{'last-run'} = eval { $get_cluster_last_run->($jobid) };
                my $last_run = $job->{'last-run'} // time(); # current time as fallback

                my $calendar_event = Proxmox::RS::CalendarEvent->new($schedule);
                my $next_run = $calendar_event->compute_next_event($last_run);
                $job->{'next-run'} = $next_run if defined($next_run);
            }

            push @$res, $job;
        }

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'read_job',
    path => '{id}',
    method => 'GET',
    description => "Read realm-sync job definition.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            id => {
                type => 'string',
                format => 'pve-configid',
            },
        },
    },
    returns => {
        type => 'object',
    },
    code => sub {
        my ($param) = @_;

        my $jobs = cfs_read_file('jobs.cfg');
        my $id = $param->{id};
        my $job = $jobs->{ids}->{$id};
        return $job if $job && $job->{type} eq 'realm-sync';

        raise_param_exc({ id => "No such job '$id'" });

    },
});

__PACKAGE__->register_method({
    name => 'create_job',
    path => '{id}',
    method => 'POST',
    protected => 1,
    description => "Create new realm-sync job.",
    permissions => {
        description => "'Realm.AllocateUser' on '/access/realm/<realm>' and "
            . "'User.Modify' permissions to '/access/groups/'.",
        check => [
            'and',
            ['perm', '/access/realm/{realm}', ['Realm.AllocateUser']],
            ['perm', '/access/groups', ['User.Modify']],
        ],
    },
    parameters => PVE::Jobs::RealmSync->createSchema(),
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $id = extract_param($param, 'id');

        cfs_lock_file(
            'jobs.cfg',
            undef,
            sub {
                my $data = cfs_read_file('jobs.cfg');

                die "Job '$id' already exists\n"
                    if $data->{ids}->{$id};

                my $plugin = PVE::Job::Registry->lookup('realm-sync');
                my $opts = $plugin->check_config($id, $param, 1, 1);

                my $realm = $opts->{realm};
                my $cfg = cfs_read_file('domains.cfg');

                raise_param_exc({ realm => "No such realm '$realm'" })
                    if !defined($cfg->{ids}->{$realm});

                my $realm_type = $cfg->{ids}->{$realm}->{type};
                raise_param_exc({ realm => "Only LDAP/AD realms can be synced." })
                    if $realm_type ne 'ldap' && $realm_type ne 'ad';

                $data->{ids}->{$id} = $opts;

                cfs_write_file('jobs.cfg', $data);
            },
        );
        die "$@" if ($@);

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'update_job',
    path => '{id}',
    method => 'PUT',
    protected => 1,
    description => "Update realm-sync job definition.",
    permissions => {
        description => "'Realm.AllocateUser' on '/access/realm/<realm>' and 'User.Modify'"
            . " permissions to '/access/groups/'.",
        check => [
            'and',
            ['perm', '/access/realm/{realm}', ['Realm.AllocateUser']],
            ['perm', '/access/groups', ['User.Modify']],
        ],
    },
    parameters => PVE::Jobs::RealmSync->updateSchema(),
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $id = extract_param($param, 'id');
        my $delete = extract_param($param, 'delete');
        $delete = [PVE::Tools::split_list($delete)] if $delete;

        die "no job options specified\n" if !scalar(keys %$param);

        cfs_lock_file(
            'jobs.cfg',
            undef,
            sub {
                my $jobs = cfs_read_file('jobs.cfg');

                my $plugin = PVE::Job::Registry->lookup('realm-sync');
                my $opts = $plugin->check_config($id, $param, 0, 1);

                my $job = $jobs->{ids}->{$id};
                die "no such realm-sync job\n" if !$job || $job->{type} ne 'realm-sync';

                my $options = $plugin->options();
                PVE::SectionConfig::delete_from_config($job, $options, $opts, $delete);

                $job->{$_} = $param->{$_} for keys $param->%*;

                cfs_write_file('jobs.cfg', $jobs);

                return;
            },
        );
        die "$@" if ($@);
    },
});

__PACKAGE__->register_method({
    name => 'delete_job',
    path => '{id}',
    method => 'DELETE',
    description => "Delete realm-sync job definition.",
    permissions => {
        check => ['perm', '/', ['Sys.Modify']],
    },
    protected => 1,
    parameters => {
        additionalProperties => 0,
        properties => {
            id => {
                type => 'string',
                format => 'pve-configid',
            },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $id = $param->{id};

        cfs_lock_file(
            'jobs.cfg',
            undef,
            sub {
                my $jobs = cfs_read_file('jobs.cfg');

                if (
                    !defined($jobs->{ids}->{$id})
                    || $jobs->{ids}->{$id}->{type} ne 'realm-sync'
                ) {
                    raise_param_exc({ id => "No such job '$id'" });
                }
                delete $jobs->{ids}->{$id};

                cfs_write_file('jobs.cfg', $jobs);
                PVE::Jobs::RealmSync::save_state($id, undef);
            },
        );
        die "$@" if $@;

        return undef;
    },
});

1;
