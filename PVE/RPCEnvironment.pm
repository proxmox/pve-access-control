package PVE::RPCEnvironment;

use strict;
use warnings;
use POSIX qw(:sys_wait_h EINTR);
use IO::File;
use Fcntl qw(:flock);
use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::Cluster;
use PVE::ProcFSTools;
use PVE::AccessControl;

# we use this singleton class to pass RPC related environment values

my $pve_env;

# save $SIG{CHLD} handler implementation.
# simply set $SIG{CHLD} = $worker_reaper;
# and register forked processes with &$register_worker(pid)
# Note: using $SIG{CHLD} = 'IGNORE' or $SIG{CHLD} = sub { wait (); } or ...
# has serious side effects, because perls built in system() and open()
# functions can't get the correct exit status of a child. So we cant use 
# that (also see perlipc)

my $WORKER_PIDS;

my $log_task_result = sub {
    my ($upid, $user, $status) = @_;

    my $msg = 'successful';
    my $pri = 'info';
    if ($status != 0) {
	my $ec = $status >> 8;
	my $ic = $status & 255;
	$msg = $ec ? "failed ($ec)" : "interrupted ($ic)";
	$pri = 'err';
    }
    my $tlist = active_workers($upid);
    PVE::Cluster::broadcast_tasklist($tlist);
    my $task;
    foreach my $t (@$tlist) {
	if ($t->{upid} eq $upid) {
	    $task = $t;
	    last;
	}
    }
    if ($task && $task->{status}) {
	$msg = $task->{status};
    }
    PVE::Cluster::log_msg($pri, $user, "end task $upid $msg");
};

my $worker_reaper = sub {
    local $!; local $?;
    foreach my $pid (keys %$WORKER_PIDS) {
        my $waitpid = waitpid ($pid, WNOHANG);
        if (defined($waitpid) && ($waitpid == $pid)) {
	    my $info = $WORKER_PIDS->{$pid};
	    if ($info && $info->{upid} && $info->{user}) {
		&$log_task_result($info->{upid}, $info->{user}, $?);
	    }
            delete ($WORKER_PIDS->{$pid});
	}
    }
};

my $register_worker = sub {
    my ($pid, $user, $upid) = @_;

    return if !$pid;

    # do not register if already finished
    my $waitpid = waitpid ($pid, WNOHANG);
    if (defined($waitpid) && ($waitpid == $pid)) {
	delete ($WORKER_PIDS->{$pid});
	return;
    }

    $WORKER_PIDS->{$pid} = {
	user => $user,
	upid => $upid,
    };
};

# ACL cache

my $compile_acl = sub {
    my ($self, $user) = @_;

    my $res = {};
    my $cfg = $self->{user_cfg};

    return undef if !$cfg->{roles};

    if ($user eq 'root@pam') { # root can do anything
	return {'/' => $cfg->{roles}->{'Administrator'}};
    } 

    foreach my $path (sort keys %{$cfg->{acl}}) {
	my @ra = PVE::AccessControl::roles($cfg, $user, $path);

	my $privs = {};
	foreach my $role (@ra) {
	    if (my $privset = $cfg->{roles}->{$role}) {
		foreach my $p (keys %$privset) {
		    $privs->{$p} = 1;
		}
	    }
	}

	$res->{$path} = $privs;
    }

    return $res;
};

sub permissions {
    my ($self, $user, $path) = @_;

    $user = PVE::AccessControl::verify_username($user, 1);
    return {} if !$user;

    my $cache = $self->{aclcache};

    my $acl = $cache->{$user};

    if (!$acl) {
	if (!($acl = &$compile_acl($self, $user))) {
	    return {};
	}
	$cache->{$user} = $acl;
    }

    my $perm;

    if (!($perm = $acl->{$path})) {
	$perm = {};
	foreach my $p (sort keys %$acl) {
	    my $final = ($path eq $p);
	    
	    next if !(($p eq '/') || $final || ($path =~ m|^$p/|));

	    $perm = $acl->{$p};
	}
	$acl->{$path} = $perm;
    }

    return $perm;
}

sub check {
    my ($self, $user, $path, $privs) = @_;

    my $perm = $self->permissions($user, $path);

    foreach my $priv (@$privs) {
	return undef if !$perm->{$priv};
    };

    return 1;
};

sub user_enabled {
    my ($self, $user) = @_;
    
    my $cfg = $self->{user_cfg};
    return PVE::AccessControl::user_enabled($cfg, $user);
}

# initialize environment - must be called once at program startup
sub init {
    my ($class, $type, %params) = @_;

    $class = ref($class) || $class;

    die "already initialized" if $pve_env;

    die "unknown environment type" if !$type || $type !~ m/^(cli|pub|priv)$/;

    $SIG{CHLD} = $worker_reaper;

    # environment types
    # cli  ... command started fron command line
    # pub  ... access from public server (apache)
    # priv ... access from private server (pvedaemon)
    
    my $self = {
	user_cfg => {},
	aclcache => {},
	aclversion => undef,
	type => $type,
    };

    bless $self, $class;

    foreach my $p (keys %params) {
	if ($p eq 'atfork') {
	    $self->{$p} = $params{$p};
	} else {
	    die "unknown option '$p'";
	}
    }

    $pve_env = $self;

    my ($sysname, $nodename) = POSIX::uname();

    $nodename =~ s/\..*$//; # strip domain part, if any

    $self->{nodename} = $nodename;

    return $self;
}; 

# get the singleton 
sub get {

    die "not initialized" if !$pve_env;

    return $pve_env;
}

# init_request - must be called before each RPC request
sub init_request {
    my ($self, %params) = @_;

    PVE::Cluster::cfs_update();

    my $userconfig; # we use this for regression tests
    foreach my $p (keys %params) {
	if ($p eq 'userconfig') {
	    $userconfig = $params{$p};
	} else {
	    die "unknown parameter '$p'";
	}
    }

    eval {
	$self->{aclcache} = {};
	if ($userconfig) {
	    my $ucdata = PVE::Tools::file_get_contents($userconfig);
	    my $cfg = PVE::AccessControl::parse_user_config($userconfig, $ucdata);
	    $self->{user_cfg} = $cfg;
	} else {
	    my $ucvers = PVE::Cluster::cfs_file_version('user.cfg'); 
	    if (!$self->{aclcache} || !defined($self->{aclversion}) || 
		!defined($ucvers) ||  ($ucvers ne $self->{aclversion})) {
		$self->{aclversion} = $ucvers;
		my $cfg = PVE::Cluster::cfs_read_file('user.cfg');
		$self->{user_cfg} = $cfg;
	    }
	}
    };
    if (my $err = $@) {
	$self->{user_cfg} = {};
	die "Unable to load access control list: $err";
    }
}

sub set_client_ip {
    my ($self, $ip) = @_;

    $self->{client_ip} = $ip;
}

sub get_client_ip {
    my ($self) = @_;

    return $self->{client_ip};
}

sub set_result_count {
    my ($self, $count) = @_;

    $self->{result_count} = $count;
}

sub get_result_count {
    my ($self) = @_;

    return $self->{result_count};
}

sub set_language {
    my ($self, $lang) = @_;

    # fixme: initialize I18N

    $self->{language} = $lang;
}

sub get_language {
    my ($self) = @_;

    return $self->{language};
}

sub set_user {
    my ($self, $user) = @_;

    # fixme: get ACLs

    $self->{user} = $user;
}

sub get_user {
    my ($self) = @_;

    die "user name not set\n" if !$self->{user};

    return $self->{user};
}

# read/update list of active workers 
# we move all finished tasks to the archive index,
# but keep aktive and most recent task in the active file.
# $nocheck ... consider $new_upid still running (avoid that
# we try to read the reult to early.
sub active_workers  {
    my ($new_upid, $nocheck) = @_;

    my $lkfn = "/var/log/pve/tasks/.active.lock";

    my $timeout = 10;

    my $code = sub {

	my $tasklist = PVE::INotify::read_file('active');

	my @ta;
	my $tlist = [];
	my $thash = {}; # only list task once

	my $check_task = sub {
	    my ($task, $running) = @_;

	    if ($running || PVE::ProcFSTools::check_process_running($task->{pid}, $task->{pstart})) {
		push @$tlist, $task;
	    } else {
		delete $task->{pid};
		push @ta, $task;
	    }
	    delete $task->{pstart};
	};

	foreach my $task (@$tasklist) {
	    my $upid = $task->{upid};
	    next if $thash->{$upid};
	    $thash->{$upid} = $task;
	    &$check_task($task);
	}

	if ($new_upid && !(my $task = $thash->{$new_upid})) {
	    $task = PVE::Tools::upid_decode($new_upid);
	    $task->{upid} = $new_upid;
	    $thash->{$new_upid} = $task;
	    &$check_task($task, $nocheck);
	}


	@ta = sort { $b->{starttime} cmp $a->{starttime} } @ta;

	my $save = defined($new_upid);

	foreach my $task (@ta) {
	    next if $task->{endtime};
	    $task->{endtime} = time();
	    $task->{status} = PVE::Tools::upid_read_status($task->{upid});
	    $save = 1;
	}

	my $archive = '';
	my @arlist = ();
	foreach my $task (@ta) {
	    if (!$task->{saved}) {
		$archive .= sprintf("$task->{upid} %08X $task->{status}\n", $task->{endtime});
		$save = 1;
		push @arlist, $task;
		$task->{saved} = 1;
	    }
	}

	if ($archive) {
	    my $size = 0;
	    my $filename = "/var/log/pve/tasks/index";
	    eval {
		my $fh = IO::File->new($filename, '>>', 0644) ||
		    die "unable to open file '$filename' - $!\n";
		PVE::Tools::safe_print($filename, $fh, $archive);
		$size = -s $fh;
		close($fh) ||
		    die "unable to close file '$filename' - $!\n";
	    };
	    my $err = $@;
	    if ($err) {
		syslog('err', $err);
		foreach my $task (@arlist) { # mark as not saved
		    $task->{saved} = 0;
		}
	    }
	    my $maxsize = 50000; # about 1000 entries
	    if ($size > $maxsize) {
		rename($filename, "$filename.1");
	    }
	}

	# we try to reduce the amount of data
	# list all running tasks and task and a few others
	# try to limit to 25 tasks
	my $ctime = time();
	my $max = 25 - scalar(@$tlist);
        foreach my $task (@ta) {
	    last if $max <= 0;
	    push @$tlist, $task;
	    $max--;
	}

	PVE::INotify::write_file('active', $tlist) if $save;

	return $tlist;
    };

    my $res = PVE::Tools::lock_file($lkfn, $timeout, $code);
    die $@ if $@;

    return $res;
}

my $kill_process_group = sub {
    my ($pid, $pstart) = @_;

    # send kill to process group (negative pid)
    my $kpid = -$pid;

    # always send signal to all pgrp members
    kill(15, $kpid); # send TERM signal

    # give max 5 seconds to shut down
    for (my $i = 0; $i < 5; $i++) {
	return if !PVE::ProcFSTools::check_process_running($pid, $pstart);
	sleep (1);
    }
       
    # to be sure
    kill(9, $kpid); 
};

sub check_worker {
    my ($upid, $killit) = @_;

    my $task = PVE::Tools::upid_decode($upid);

    my $running = PVE::ProcFSTools::check_process_running($task->{pid}, $task->{pstart});

    return 0 if !$running;

    if ($killit) {
	&$kill_process_group($task->{pid});
	return 0;
    }

    return 1;
}

# start long running workers
# STDIN is redirected to /dev/null
# STDOUT,STDERR are redirected to the filename returned by upid_decode
# NOTE: we simulate running in foreground if ($self->{type} eq 'cli')
sub fork_worker {
    my ($self, $dtype, $id, $user, $function) = @_;

    $dtype = 'unknown' if !defined ($dtype);
    $id = '' if !defined ($id);

    $user = 'root@pve' if !defined ($user);

    my $sync = $self->{type} eq 'cli' ? 1 : 0;

    local $SIG{INT} = 
	local $SIG{QUIT} = 
	local $SIG{PIPE} = 
	local $SIG{TERM} = 'IGNORE';

    my $starttime = time ();

    my @psync = POSIX::pipe();
    my @csync = POSIX::pipe();

    my $node = $self->{nodename};

    my $cpid = fork();
    die "unable to fork worker - $!" if !defined($cpid);

    my $workerpuid = $cpid ? $cpid : $$;

    my $pstart = PVE::ProcFSTools::read_proc_starttime($workerpuid) ||
	die "unable to read process start time";

    my $upid = PVE::Tools::upid_encode ({
	node => $node, pid => $workerpuid, pstart => $pstart, 
	starttime => $starttime, type => $dtype, id => $id, user => $user });

    my $outfh;

    if (!$cpid) { # child

	$0 = "task $upid";

	$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub { die "received interrupt\n"; };

	$SIG{CHLD} = $SIG{PIPE} = 'DEFAULT';

	# set sess/process group - we want to be able to kill the
	# whole process group
	POSIX::setsid(); 

	POSIX::close ($psync[0]);
	POSIX::close ($csync[1]);

	$outfh = $sync ? $psync[1] : undef;

	eval {
	    PVE::INotify::inotify_close();

	    if (my $atfork = $self->{atfork}) {
		&$atfork();
	    }

	    # same algorythm as used inside SA
	    # STDIN = /dev/null
	    my $fd = fileno (STDIN);
	    close STDIN;
	    POSIX::close(0) if $fd != 0;

	    die "unable to redirect STDIN - $!" 
		if !open(STDIN, "</dev/null");

	    $outfh = PVE::Tools::upid_open($upid) if !$sync;

	    # redirect STDOUT
	    $fd = fileno(STDOUT);
	    close STDOUT;
	    POSIX::close (1) if $fd != 1;

	    die "unable to redirect STDOUT - $!" 
		if !open(STDOUT, ">&", $outfh);

	    STDOUT->autoflush (1);
      
	    #  redirect STDERR to STDOUT
	    $fd = fileno (STDERR);
	    close STDERR;
	    POSIX::close(2) if $fd != 2;

	    die "unable to redirect STDERR - $!" 
		if !open(STDERR, ">&1");
	    
	    STDERR->autoflush(1);
	};
	if (my $err = $@) {
	    my $msg =  "ERROR: $err";
	    POSIX::write($psync[1], $msg, length ($msg));
	    POSIX::close($psync[1]);
	    POSIX::_exit(1); 
	    kill(-9, $$); 
	}

	# sync with parent (signal that we are ready)
	if ($sync) {
	    print "$upid\n";
	} else {
	    POSIX::write($psync[1], $upid, length ($upid));
	    POSIX::close($psync[1]);
	}

	my $readbuf = '';
	# sync with parent (wait until parent is ready)
	POSIX::read($csync[0], $readbuf, 4096);
	die "parent setup error\n" if $readbuf ne 'OK';

	eval { &$function($upid); };
	my $err = $@;
	if ($err) {
	    chomp $err;
	    $err =~ s/\n/ /mg;
	    syslog('err', $err);
	    print STDERR "TASK ERROR: $err\n";
	    POSIX::_exit(-1); 
	} else {
	    print STDERR "TASK OK\n";
	    POSIX::_exit(0);
	} 
	kill(-9, $$); 
    }

    # parent

    POSIX::close ($psync[1]);
    POSIX::close ($csync[0]);

    my $readbuf = '';
    # sync with child (wait until child starts)
    POSIX::read($psync[0], $readbuf, 4096);

    if (!$sync) {
	POSIX::close($psync[0]);
	&$register_worker($cpid, $user, $upid);
    } else {
	chomp $readbuf;
    }

    eval {
	die "got no worker upid - start worker failed\n" if !$readbuf;

	if ($readbuf =~ m/^ERROR:\s*(.+)$/m) {
	    die "starting worker failed: $1\n";
	}

	if ($readbuf ne $upid) {
	    die "got strange worker upid ('$readbuf' != '$upid') - start worker failed\n";
	}

	if ($sync) {
	    $outfh = PVE::Tools::upid_open($upid);
	}
    };
    my $err = $@;

    if (!$err) {
	my $msg = 'OK';
	POSIX::write($csync[1], $msg, length ($msg));
	POSIX::close($csync[1]);
       
    } else {
	POSIX::close($csync[1]);
	kill(-9, $cpid); # make sure it gets killed
	die $err;
    }

    PVE::Cluster::log_msg('info', $user, "starting task $upid");

    my $tlist = active_workers($upid, $sync);
    PVE::Cluster::broadcast_tasklist($tlist);
   
    my $res = 0;

    if ($sync) {
	my $count;
	my $outbuf = '';
	my $int_count = 0;
	eval {
	    local $SIG{INT} = local $SIG{QUIT} = local $SIG{TERM} = sub { 
		if ($int_count < 3) {
		    kill(15, $cpid); # send TERM signal
		} else {
		    kill(9, $cpid); # send KILL signal
		}
		$int_count++;
	    };
	    local $SIG{PIPE} = sub { die "broken pipe\n"; };
	
	    while (1) {
		if (!defined($count = POSIX::read($psync[0], $readbuf, 4096))) {
		    next if $! == EINTR;
		    last;
		}
		last if $count == 0; # eof

		$outbuf .= $readbuf;
		while ($outbuf =~ s/^(([^\010\r\n]*)(\r|\n|(\010)+|\r\n))//s) {
		    my $line = $1;
		    my $data = $2;
		    if ($data =~ m/^TASK OK$/) {
			# skip
		    } elsif ($data =~ m/^TASK ERROR: (.+)$/) {
			print STDERR "$1\n";
		    } else {
			print $line;
		    }
		    if ($outfh) {
			print $outfh $line;
			$outfh->flush();
		    }
		}
	    }
	};
	my $err = $@;

	POSIX::close($psync[0]);

	if ($outbuf) { # just to be sure
	    print $outbuf;
	    if ($outfh) {
		print $outfh $outbuf;
	    }
	}

	if ($err) {
	    $err =~ s/\n/ /mg;
	    print STDERR "$err\n";
	    if ($outfh) {
		print $outfh "TASK ERROR: $err\n";
	    }
	}

	&$kill_process_group($cpid, $pstart); # make sure it gets killed

	close($outfh);

	waitpid($cpid, 0);
	$res = $?;
	&$log_task_result($upid, $user, $res);
    }

    return wantarray ? ($upid, $res) : $upid;
}

1;
