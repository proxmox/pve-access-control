package PVE::Jobs::RealmSync;

use strict;
use warnings;

use JSON qw(decode_json encode_json);
use POSIX qw(ENOENT);

use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster ();
use PVE::CalendarEvent ();
use PVE::Tools ();

use PVE::API2::Domains ();

# load user-* standard options
use PVE::API2::User ();

use base qw(PVE::Job::Registry);

sub type {
    return 'realm-sync';
}

my $props = get_standard_option('realm-sync-options', {
        realm => get_standard_option('realm'),
});

sub properties {
    return $props;
}

sub options {
    my $options = {
        enabled => { optional => 1 },
        schedule => {},
        comment => { optional => 1 },
        scope => {},
    };
    for my $opt (keys %$props) {
        next if defined($options->{$opt});
        # ignore legacy props from realm-sync schema
        next if $opt eq 'full' || $opt eq 'purge';
        if ($props->{$opt}->{optional}) {
            $options->{$opt} = { optional => 1 };
        } else {
            $options->{$opt} = {};
        }
    }
    $options->{realm}->{fixed} = 1;

    return $options;
}

sub decode_value {
    my ($class, $type, $key, $value) = @_;
    return $value;
}

sub encode_value {
    my ($class, $type, $key, $value) = @_;
    return $value;
}

sub createSchema {
    my ($class, $skip_type) = @_;

    my $schema = $class->SUPER::createSchema($skip_type);

    my $opts = $class->options();
    for my $opt (keys $schema->{properties}->%*) {
        next if defined($opts->{$opt}) || $opt eq 'id';
        delete $schema->{properties}->{$opt};
    }

    return $schema;
}

sub updateSchema {
    my ($class, $skip_type) = @_;
    my $schema = $class->SUPER::updateSchema($skip_type);

    my $opts = $class->options();
    for my $opt (keys $schema->{properties}->%*) {
        next if defined($opts->{$opt});
        next if $opt eq 'id' || $opt eq 'delete';
        delete $schema->{properties}->{$opt};
    }

    return $schema;
}

my $statedir = "/etc/pve/priv/jobs";

sub get_state {
    my ($id) = @_;

    mkdir $statedir;
    my $statefile = "$statedir/realm-sync-$id.json";
    my $raw = eval { PVE::Tools::file_get_contents($statefile) } // '';

    my $state = ($raw =~ m/^(\{.*\})$/) ? decode_json($1) : {};

    return $state;
}

sub save_state {
    my ($id, $state) = @_;

    mkdir $statedir;
    my $statefile = "$statedir/realm-sync-$id.json";

    if (defined($state)) {
        PVE::Tools::file_set_contents($statefile, encode_json($state));
    } else {
        unlink $statefile or $! == ENOENT or die "could not delete state for $id - $!\n";
    }

    return undef;
}

sub run {
    my ($class, $conf, $id, $schedule) = @_;

    for my $opt (keys %$conf) {
        delete $conf->{$opt} if !defined($props->{$opt});
    }

    my $realm = $conf->{realm};

    # cluster synced
    my $now = time();
    my $nodename = PVE::INotify::nodename();

    # check statefile in pmxcfs if we should start
    my $shouldrun = PVE::Cluster::cfs_lock_domain(
        'realm-sync',
        undef,
        sub {
            my $members = PVE::Cluster::get_members();

            my $state = get_state($id);
            my $last_node = $state->{node} // $nodename;
            my $last_upid = $state->{upid};
            my $last_time = $state->{time};

            my $last_node_online =
                $last_node eq $nodename || ($members->{$last_node} // {})->{online};

            if (defined($last_upid)) {
                # first check if the next run is scheduled
                if (my $parsed = PVE::Tools::upid_decode($last_upid, 1)) {
                    my $cal_spec = PVE::CalendarEvent::parse_calendar_event($schedule);
                    my $next_sync =
                        PVE::CalendarEvent::compute_next_event($cal_spec, $parsed->{starttime});
                    return 0 if !defined($next_sync) || $now < $next_sync; # not yet its (next) turn
                }
                # check if still running and node is online
                my $tasks = PVE::Cluster::get_tasklist();
                for my $task (@$tasks) {
                    next if $task->{upid} ne $last_upid;
                    last if defined($task->{endtime}); # it's already finished
                    last if !$last_node_online; # it's not finished and the node is offline
                    return 0; # not finished and online
                }
            } elsif (defined($last_time) && ($last_time + 60) > $now && $last_node_online) {
                # another node started this job in the last 60 seconds and is still online
                return 0;
            }

            # any of the following conditions should be true here:
            # * it was started on another node but that node is offline now
            # * it was started but either too long ago, or with an error
            # * the started task finished

            save_state(
                $id,
                {
                    node => $nodename,
                    time => $now,
                },
            );
            return 1;
        },
    );
    die $@ if $@;

    if ($shouldrun) {
        my $upid = eval { PVE::API2::Domains->sync($conf) };
        my $err = $@;
        PVE::Cluster::cfs_lock_domain(
            'realm-sync',
            undef,
            sub {
                if ($err && !$upid) {
                    save_state(
                        $id,
                        {
                            node => $nodename,
                            time => $now,
                            error => $err,
                        },
                    );
                    die "$err\n";
                }

                save_state(
                    $id,
                    {
                        node => $nodename,
                        upid => $upid,
                    },
                );
            },
        );
        die $@ if $@;
        return $upid;
    }

    return "OK"; # all other cases should not run the sync on this node
}

1;
