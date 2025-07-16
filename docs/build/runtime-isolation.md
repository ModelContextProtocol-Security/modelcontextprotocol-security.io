---
layout: default
title: "Runtime Isolation"
permalink: /build/runtime-isolation/
nav_order: 3
parent: "Build Security"
---

# Runtime Isolation

**Overview**: Sandboxing and privilege isolation techniques for secure MCP tool execution.

Runtime isolation is critical for containing MCP tools and preventing them from accessing unauthorized resources or affecting the host system. This guide covers containerization, sandboxing, and privilege isolation techniques.

## Container-Based Isolation

### Docker Container Isolation

```python
# Docker-based tool isolation
import docker
import tempfile
import json
from pathlib import Path

class DockerToolIsolation:
    def __init__(self):
        self.client = docker.from_env()
        self.base_image = "python:3.11-slim"
        self.network_mode = "none"  # No network access by default
        
    def create_secure_container(self, tool_config: dict) -> str:
        """Create secure container for tool execution"""
        
        # Create temporary directory for tool files
        temp_dir = tempfile.mkdtemp()
        
        # Prepare container configuration
        container_config = {
            'image': self.base_image,
            'working_dir': '/app',
            'volumes': {
                temp_dir: {'bind': '/app', 'mode': 'rw'}
            },
            'network_mode': self.network_mode,
            'user': 'nobody',  # Non-root user
            'mem_limit': '128m',  # Memory limit
            'cpu_quota': 50000,  # CPU quota (50% of one core)
            'read_only': True,  # Read-only filesystem
            'security_opt': ['no-new-privileges'],
            'cap_drop': ['ALL'],  # Drop all capabilities
            'cap_add': [],  # Add only necessary capabilities
            'environment': self.get_safe_environment(),
            'tmpfs': {
                '/tmp': 'rw,noexec,nosuid,size=10m'
            }
        }
        
        # Create and configure container
        container = self.client.containers.create(**container_config)
        
        # Apply additional security configurations
        self.apply_security_configurations(container, tool_config)
        
        return container.id
    
    def apply_security_configurations(self, container, tool_config):
        """Apply additional security configurations"""
        
        # Configure resource limits
        self.configure_resource_limits(container, tool_config)
        
        # Configure network restrictions
        self.configure_network_restrictions(container, tool_config)
        
        # Configure filesystem restrictions
        self.configure_filesystem_restrictions(container, tool_config)
        
        # Configure syscall filtering
        self.configure_syscall_filtering(container, tool_config)
    
    def configure_resource_limits(self, container, tool_config):
        """Configure resource limits for container"""
        
        limits = tool_config.get('resource_limits', {})
        
        # Memory limit
        memory_limit = limits.get('memory', '128m')
        container.update(mem_limit=memory_limit)
        
        # CPU limit
        cpu_quota = limits.get('cpu_quota', 50000)
        container.update(cpu_quota=cpu_quota)
        
        # Process limit
        pids_limit = limits.get('pids_limit', 50)
        container.update(pids_limit=pids_limit)
    
    def execute_tool_safely(self, container_id: str, tool_command: str) -> dict:
        """Execute tool in isolated container"""
        
        container = self.client.containers.get(container_id)
        
        try:
            # Start container
            container.start()
            
            # Execute tool command with timeout
            result = container.exec_run(
                tool_command,
                user='nobody',
                environment=self.get_safe_environment(),
                workdir='/app'
            )
            
            return {
                'exit_code': result.exit_code,
                'output': result.output.decode('utf-8'),
                'success': result.exit_code == 0
            }
            
        except Exception as e:
            return {
                'exit_code': -1,
                'output': f"Execution error: {str(e)}",
                'success': False
            }
            
        finally:
            # Clean up container
            container.stop(timeout=5)
            container.remove()
    
    def get_safe_environment(self) -> dict:
        """Get safe environment variables for container"""
        
        return {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': '/tmp',
            'USER': 'nobody',
            'SHELL': '/bin/sh'
        }
```

### gVisor Integration

```python
# gVisor-based advanced isolation
import subprocess
import json
import tempfile

class GVisorIsolation:
    def __init__(self):
        self.runtime = "runsc"
        self.config_dir = "/etc/runsc"
        
    def create_gvisor_container(self, tool_config: dict) -> str:
        """Create gVisor-isolated container"""
        
        # Generate container configuration
        container_config = self.generate_container_config(tool_config)
        
        # Create container with gVisor runtime
        container_id = self.create_container_with_runsc(container_config)
        
        return container_id
    
    def generate_container_config(self, tool_config: dict) -> dict:
        """Generate OCI container configuration for gVisor"""
        
        config = {
            "ociVersion": "1.0.0",
            "process": {
                "terminal": False,
                "user": {"uid": 65534, "gid": 65534},  # nobody user
                "args": tool_config.get('command', ['/bin/sh']),
                "env": [
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                    "HOME=/tmp",
                    "USER=nobody"
                ],
                "cwd": "/app",
                "capabilities": {
                    "bounding": [],
                    "effective": [],
                    "inheritable": [],
                    "permitted": []
                },
                "rlimits": [
                    {
                        "type": "RLIMIT_NOFILE",
                        "hard": 1024,
                        "soft": 1024
                    },
                    {
                        "type": "RLIMIT_NPROC",
                        "hard": 50,
                        "soft": 50
                    }
                ]
            },
            "root": {
                "path": tool_config.get('rootfs', '/tmp/rootfs'),
                "readonly": True
            },
            "hostname": "isolated-tool",
            "mounts": self.generate_secure_mounts(tool_config),
            "linux": {
                "resources": {
                    "memory": {
                        "limit": 134217728  # 128MB
                    },
                    "cpu": {
                        "quota": 50000,
                        "period": 100000
                    }
                },
                "namespaces": [
                    {"type": "pid"},
                    {"type": "network"},
                    {"type": "ipc"},
                    {"type": "uts"},
                    {"type": "mount"},
                    {"type": "user"}
                ],
                "seccomp": self.generate_seccomp_profile()
            }
        }
        
        return config
    
    def generate_secure_mounts(self, tool_config: dict) -> list:
        """Generate secure mount configuration"""
        
        mounts = [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"]
            },
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"]
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "noexec", "size=10m"]
            },
            {
                "destination": "/dev/null",
                "type": "bind",
                "source": "/dev/null",
                "options": ["bind", "ro"]
            }
        ]
        
        # Add tool-specific mounts if allowed
        if tool_config.get('allow_file_access'):
            mounts.append({
                "destination": "/app/data",
                "type": "bind",
                "source": tool_config.get('data_dir', '/tmp/tool-data'),
                "options": ["bind", "ro"]
            })
        
        return mounts
    
    def generate_seccomp_profile(self) -> dict:
        """Generate seccomp profile for syscall filtering"""
        
        return {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": [
                        "read", "write", "open", "close", "stat", "fstat",
                        "lstat", "poll", "lseek", "mmap", "mprotect",
                        "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
                        "ioctl", "access", "pipe", "select", "sched_yield",
                        "mremap", "msync", "mincore", "madvise", "shmget",
                        "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep",
                        "getitimer", "alarm", "setitimer", "getpid", "sendfile",
                        "socket", "connect", "accept", "sendto", "recvfrom",
                        "sendmsg", "recvmsg", "shutdown", "bind", "listen",
                        "getsockname", "getpeername", "socketpair", "setsockopt",
                        "getsockopt", "clone", "fork", "vfork", "execve",
                        "exit", "wait4", "kill", "uname", "semget", "semop",
                        "semctl", "shmdt", "msgget", "msgsnd", "msgrcv",
                        "msgctl", "fcntl", "flock", "fsync", "fdatasync",
                        "truncate", "ftruncate", "getdents", "getcwd",
                        "chdir", "fchdir", "rename", "mkdir", "rmdir",
                        "creat", "link", "unlink", "symlink", "readlink",
                        "chmod", "fchmod", "chown", "fchown", "lchown",
                        "umask", "gettimeofday", "getrlimit", "getrusage",
                        "sysinfo", "times", "ptrace", "getuid", "syslog",
                        "getgid", "setuid", "setgid", "geteuid", "getegid",
                        "setpgid", "getppid", "getpgrp", "setsid", "setreuid",
                        "setregid", "getgroups", "setgroups", "setresuid",
                        "getresuid", "setresgid", "getresgid", "getpgid",
                        "setfsuid", "setfsgid", "getsid", "capget", "capset",
                        "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
                        "rt_sigsuspend", "sigaltstack", "utime", "mknod",
                        "uselib", "personality", "ustat", "statfs", "fstatfs",
                        "sysfs", "getpriority", "setpriority", "sched_setparam",
                        "sched_getparam", "sched_setscheduler", "sched_getscheduler",
                        "sched_get_priority_max", "sched_get_priority_min",
                        "sched_rr_get_interval", "mlock", "munlock", "mlockall",
                        "munlockall", "vhangup", "modify_ldt", "pivot_root",
                        "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
                        "chroot", "sync", "acct", "settimeofday", "mount",
                        "umount2", "swapon", "swapoff", "reboot", "sethostname",
                        "setdomainname", "iopl", "ioperm", "create_module",
                        "init_module", "delete_module", "get_kernel_syms",
                        "query_module", "quotactl", "nfsservctl", "getpmsg",
                        "putpmsg", "afs_syscall", "tuxcall", "security",
                        "gettid", "readahead", "setxattr", "lsetxattr",
                        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
                        "listxattr", "llistxattr", "flistxattr", "removexattr",
                        "lremovexattr", "fremovexattr", "tkill", "time",
                        "futex", "sched_setaffinity", "sched_getaffinity",
                        "set_thread_area", "io_setup", "io_destroy", "io_getevents",
                        "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie",
                        "epoll_create", "epoll_ctl_old", "epoll_wait_old",
                        "remap_file_pages", "getdents64", "set_tid_address",
                        "restart_syscall", "semtimedop", "fadvise64", "timer_create",
                        "timer_settime", "timer_gettime", "timer_getoverrun",
                        "timer_delete", "clock_settime", "clock_gettime",
                        "clock_getres", "clock_nanosleep", "exit_group",
                        "epoll_wait", "epoll_ctl", "tgkill", "utimes",
                        "vserver", "mbind", "set_mempolicy", "get_mempolicy",
                        "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
                        "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
                        "add_key", "request_key", "keyctl", "ioprio_set",
                        "ioprio_get", "inotify_init", "inotify_add_watch",
                        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
                        "mknodat", "fchownat", "futimesat", "newfstatat",
                        "unlinkat", "renameat", "linkat", "symlinkat",
                        "readlinkat", "fchmodat", "faccessat", "pselect6",
                        "ppoll", "unshare", "set_robust_list", "get_robust_list",
                        "splice", "tee", "sync_file_range", "vmsplice",
                        "move_pages", "utimensat", "epoll_pwait", "signalfd",
                        "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
                        "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
                        "epoll_create1", "dup3", "pipe2", "inotify_init1",
                        "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
                        "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
                        "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
                        "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
                        "process_vm_writev", "kcmp", "finit_module", "sched_setattr",
                        "sched_getattr", "renameat2", "seccomp", "getrandom",
                        "memfd_create", "kexec_file_load", "bpf", "execveat",
                        "userfaultfd", "membarrier", "mlock2", "copy_file_range",
                        "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc",
                        "pkey_free", "statx", "io_pgetevents", "rseq",
                        "pidfd_send_signal", "io_uring_setup", "io_uring_enter",
                        "io_uring_register", "open_tree", "move_mount",
                        "fsopen", "fsconfig", "fsmount", "fspick", "pidfd_open",
                        "clone3", "close_range", "openat2", "pidfd_getfd",
                        "faccessat2", "process_madvise", "epoll_pwait2",
                        "mount_setattr", "quotactl_fd", "landlock_create_ruleset",
                        "landlock_add_rule", "landlock_restrict_self"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                }
            ]
        }
```

## Process-Level Isolation

### User Namespace Isolation

```python
# User namespace isolation
import os
import subprocess
import pwd
import grp

class UserNamespaceIsolation:
    def __init__(self):
        self.nobody_uid = pwd.getpwnam('nobody').pw_uid
        self.nobody_gid = grp.getgrnam('nobody').gr_gid
        
    def create_user_namespace(self, tool_config: dict) -> int:
        """Create isolated user namespace for tool execution"""
        
        # Create child process with new user namespace
        pid = os.fork()
        
        if pid == 0:
            # Child process
            self.setup_user_namespace(tool_config)
            self.execute_tool(tool_config)
            os._exit(0)
        else:
            # Parent process
            self.configure_uid_gid_mapping(pid)
            return pid
    
    def setup_user_namespace(self, tool_config: dict):
        """Setup user namespace environment"""
        
        # Unshare user namespace
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        
        CLONE_NEWUSER = 0x10000000
        CLONE_NEWPID = 0x20000000
        CLONE_NEWNET = 0x40000000
        CLONE_NEWIPC = 0x08000000
        CLONE_NEWUTS = 0x04000000
        CLONE_NEWNS = 0x00020000
        
        flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS
        
        result = libc.unshare(flags)
        if result != 0:
            raise RuntimeError("Failed to create user namespace")
        
        # Set up environment
        os.environ['HOME'] = '/tmp'
        os.environ['USER'] = 'nobody'
        os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin'
        
        # Change to nobody user
        os.setuid(self.nobody_uid)
        os.setgid(self.nobody_gid)
    
    def configure_uid_gid_mapping(self, pid: int):
        """Configure UID/GID mapping for user namespace"""
        
        # Configure UID mapping
        with open(f'/proc/{pid}/uid_map', 'w') as f:
            f.write(f'0 {self.nobody_uid} 1\n')
        
        # Deny setgroups
        with open(f'/proc/{pid}/setgroups', 'w') as f:
            f.write('deny\n')
        
        # Configure GID mapping
        with open(f'/proc/{pid}/gid_map', 'w') as f:
            f.write(f'0 {self.nobody_gid} 1\n')
```

## Filesystem Isolation

### Chroot and Bind Mount Isolation

```python
# Filesystem isolation implementation
import os
import tempfile
import shutil
import subprocess

class FilesystemIsolation:
    def __init__(self):
        self.jail_dir = None
        self.allowed_paths = ['/lib', '/lib64', '/usr/lib', '/bin', '/usr/bin']
        
    def create_filesystem_jail(self, tool_config: dict) -> str:
        """Create filesystem jail for tool execution"""
        
        # Create temporary jail directory
        self.jail_dir = tempfile.mkdtemp(prefix='mcp-jail-')
        
        # Create basic directory structure
        self.create_jail_structure()
        
        # Copy necessary files
        self.copy_essential_files(tool_config)
        
        # Setup bind mounts
        self.setup_bind_mounts(tool_config)
        
        return self.jail_dir
    
    def create_jail_structure(self):
        """Create basic jail directory structure"""
        
        directories = [
            'bin', 'lib', 'lib64', 'usr/bin', 'usr/lib',
            'tmp', 'proc', 'sys', 'dev', 'app'
        ]
        
        for directory in directories:
            os.makedirs(os.path.join(self.jail_dir, directory), exist_ok=True)
    
    def copy_essential_files(self, tool_config: dict):
        """Copy essential files to jail"""
        
        # Copy shell and basic utilities
        essential_binaries = [
            '/bin/sh', '/bin/ls', '/bin/cat', '/bin/echo',
            '/usr/bin/python3', '/usr/bin/env'
        ]
        
        for binary in essential_binaries:
            if os.path.exists(binary):
                jail_path = os.path.join(self.jail_dir, binary.lstrip('/'))
                os.makedirs(os.path.dirname(jail_path), exist_ok=True)
                shutil.copy2(binary, jail_path)
        
        # Copy libraries
        self.copy_libraries()
        
        # Copy tool-specific files
        self.copy_tool_files(tool_config)
    
    def copy_libraries(self):
        """Copy essential libraries to jail"""
        
        # Find and copy shared libraries
        lib_dirs = ['/lib', '/lib64', '/usr/lib', '/usr/lib64']
        
        for lib_dir in lib_dirs:
            if os.path.exists(lib_dir):
                jail_lib_dir = os.path.join(self.jail_dir, lib_dir.lstrip('/'))
                
                # Copy essential libraries
                for lib_file in os.listdir(lib_dir):
                    if lib_file.endswith('.so') or '.so.' in lib_file:
                        src = os.path.join(lib_dir, lib_file)
                        dst = os.path.join(jail_lib_dir, lib_file)
                        
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
    
    def copy_tool_files(self, tool_config: dict):
        """Copy tool-specific files to jail"""
        
        tool_files = tool_config.get('files', [])
        
        for file_path in tool_files:
            if os.path.exists(file_path):
                jail_path = os.path.join(self.jail_dir, 'app', os.path.basename(file_path))
                shutil.copy2(file_path, jail_path)
    
    def setup_bind_mounts(self, tool_config: dict):
        """Setup bind mounts for jail"""
        
        # Mount /proc (filtered)
        proc_path = os.path.join(self.jail_dir, 'proc')
        subprocess.run(['mount', '-t', 'proc', 'proc', proc_path], check=True)
        
        # Mount /dev (minimal)
        dev_path = os.path.join(self.jail_dir, 'dev')
        self.create_minimal_dev(dev_path)
        
        # Mount /tmp (tmpfs)
        tmp_path = os.path.join(self.jail_dir, 'tmp')
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=10m,noexec,nosuid,nodev', 'tmpfs', tmp_path], check=True)
    
    def create_minimal_dev(self, dev_path: str):
        """Create minimal /dev directory"""
        
        # Create essential device files
        devices = [
            ('null', 'c', 1, 3),
            ('zero', 'c', 1, 5),
            ('random', 'c', 1, 8),
            ('urandom', 'c', 1, 9)
        ]
        
        for name, dev_type, major, minor in devices:
            device_path = os.path.join(dev_path, name)
            subprocess.run(['mknod', device_path, dev_type, str(major), str(minor)], check=True)
    
    def execute_in_jail(self, tool_config: dict, command: str) -> dict:
        """Execute command in filesystem jail"""
        
        try:
            # Change root to jail directory
            os.chroot(self.jail_dir)
            os.chdir('/')
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool_config.get('timeout', 30)
            )
            
            return {
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exit_code': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'success': False
            }
        except Exception as e:
            return {
                'exit_code': -1,
                'stdout': '',
                'stderr': f'Execution error: {str(e)}',
                'success': False
            }
    
    def cleanup_jail(self):
        """Clean up filesystem jail"""
        
        if self.jail_dir and os.path.exists(self.jail_dir):
            # Unmount filesystems
            subprocess.run(['umount', os.path.join(self.jail_dir, 'proc')], check=False)
            subprocess.run(['umount', os.path.join(self.jail_dir, 'tmp')], check=False)
            
            # Remove jail directory
            shutil.rmtree(self.jail_dir)
```

## Network Isolation

### Network Namespace Isolation

```python
# Network isolation implementation
import socket
import subprocess

class NetworkIsolation:
    def __init__(self):
        self.allowed_hosts = []
        self.allowed_ports = []
        self.network_policies = {}
        
    def create_network_namespace(self, tool_config: dict) -> str:
        """Create isolated network namespace"""
        
        namespace_name = f"mcp-tool-{os.getpid()}"
        
        # Create network namespace
        subprocess.run(['ip', 'netns', 'add', namespace_name], check=True)
        
        # Configure network policies
        self.configure_network_policies(namespace_name, tool_config)
        
        return namespace_name
    
    def configure_network_policies(self, namespace: str, tool_config: dict):
        """Configure network policies for namespace"""
        
        # Get network configuration
        network_config = tool_config.get('network', {})
        
        if network_config.get('allow_internet', False):
            self.setup_internet_access(namespace, network_config)
        elif network_config.get('allow_local', False):
            self.setup_local_access(namespace, network_config)
        else:
            # No network access (default)
            self.setup_no_network(namespace)
    
    def setup_no_network(self, namespace: str):
        """Setup namespace with no network access"""
        
        # Only loopback interface
        subprocess.run(['ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up'], check=True)
    
    def setup_local_access(self, namespace: str, network_config: dict):
        """Setup namespace with local network access"""
        
        # Create veth pair
        veth_host = f"veth-host-{os.getpid()}"
        veth_ns = f"veth-ns-{os.getpid()}"
        
        subprocess.run(['ip', 'link', 'add', veth_host, 'type', 'veth', 'peer', 'name', veth_ns], check=True)
        
        # Move one end to namespace
        subprocess.run(['ip', 'link', 'set', veth_ns, 'netns', namespace], check=True)
        
        # Configure interfaces
        subprocess.run(['ip', 'addr', 'add', '192.168.100.1/24', 'dev', veth_host], check=True)
        subprocess.run(['ip', 'link', 'set', veth_host, 'up'], check=True)
        
        subprocess.run(['ip', 'netns', 'exec', namespace, 'ip', 'addr', 'add', '192.168.100.2/24', 'dev', veth_ns], check=True)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', veth_ns, 'up'], check=True)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up'], check=True)
        
        # Setup routing
        subprocess.run(['ip', 'netns', 'exec', namespace, 'ip', 'route', 'add', 'default', 'via', '192.168.100.1'], check=True)
        
        # Apply firewall rules
        self.apply_firewall_rules(namespace, network_config)
    
    def apply_firewall_rules(self, namespace: str, network_config: dict):
        """Apply firewall rules to namespace"""
        
        allowed_hosts = network_config.get('allowed_hosts', [])
        allowed_ports = network_config.get('allowed_ports', [])
        
        # Default deny all
        subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-P', 'INPUT', 'DROP'], check=True)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-P', 'OUTPUT', 'DROP'], check=True)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-P', 'FORWARD', 'DROP'], check=True)
        
        # Allow loopback
        subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=True)
        
        # Allow specific hosts and ports
        for host in allowed_hosts:
            for port in allowed_ports:
                subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-A', 'OUTPUT', '-d', host, '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'], check=True)
                subprocess.run(['ip', 'netns', 'exec', namespace, 'iptables', '-A', 'INPUT', '-s', host, '-p', 'tcp', '--sport', str(port), '-j', 'ACCEPT'], check=True)
    
    def execute_in_network_namespace(self, namespace: str, command: str) -> dict:
        """Execute command in network namespace"""
        
        try:
            result = subprocess.run(
                ['ip', 'netns', 'exec', namespace] + command.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'exit_code': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'success': False
            }
        except Exception as e:
            return {
                'exit_code': -1,
                'stdout': '',
                'stderr': f'Execution error: {str(e)}',
                'success': False
            }
    
    def cleanup_network_namespace(self, namespace: str):
        """Clean up network namespace"""
        
        try:
            subprocess.run(['ip', 'netns', 'del', namespace], check=True)
        except subprocess.CalledProcessError:
            pass  # Namespace may already be deleted
```

## Integration Example

### Complete Isolation System

```python
# Complete isolation system integration
class ComprehensiveIsolation:
    def __init__(self):
        self.docker_isolation = DockerToolIsolation()
        self.filesystem_isolation = FilesystemIsolation()
        self.network_isolation = NetworkIsolation()
        self.user_isolation = UserNamespaceIsolation()
        
    def execute_tool_isolated(self, tool_config: dict, command: str) -> dict:
        """Execute tool with comprehensive isolation"""
        
        isolation_method = tool_config.get('isolation_method', 'docker')
        
        if isolation_method == 'docker':
            return self.execute_with_docker(tool_config, command)
        elif isolation_method == 'namespace':
            return self.execute_with_namespaces(tool_config, command)
        elif isolation_method == 'chroot':
            return self.execute_with_chroot(tool_config, command)
        else:
            raise ValueError(f"Unknown isolation method: {isolation_method}")
    
    def execute_with_docker(self, tool_config: dict, command: str) -> dict:
        """Execute with Docker isolation"""
        
        container_id = self.docker_isolation.create_secure_container(tool_config)
        
        try:
            result = self.docker_isolation.execute_tool_safely(container_id, command)
            return result
        finally:
            # Cleanup handled by DockerToolIsolation
            pass
    
    def execute_with_namespaces(self, tool_config: dict, command: str) -> dict:
        """Execute with namespace isolation"""
        
        network_namespace = self.network_isolation.create_network_namespace(tool_config)
        
        try:
            # Execute in network namespace with user namespace
            pid = self.user_isolation.create_user_namespace(tool_config)
            
            # Wait for completion
            _, status = os.waitpid(pid, 0)
            
            return {
                'exit_code': status,
                'success': status == 0
            }
            
        finally:
            self.network_isolation.cleanup_network_namespace(network_namespace)
    
    def execute_with_chroot(self, tool_config: dict, command: str) -> dict:
        """Execute with chroot isolation"""
        
        jail_dir = self.filesystem_isolation.create_filesystem_jail(tool_config)
        
        try:
            result = self.filesystem_isolation.execute_in_jail(tool_config, command)
            return result
        finally:
            self.filesystem_isolation.cleanup_jail()
```

## Security Considerations

### Isolation Best Practices

1. **Defense in Depth**: Use multiple isolation layers
2. **Least Privilege**: Grant minimal necessary permissions
3. **Resource Limits**: Implement strict resource quotas
4. **Network Isolation**: Restrict network access by default
5. **Monitoring**: Log and monitor isolated environments

### Common Isolation Bypasses

- **Kernel Exploits**: Container escapes through kernel vulnerabilities
- **Privilege Escalation**: Exploiting SUID binaries or capabilities
- **Resource Exhaustion**: Consuming host resources through containers
- **Network Escapes**: Bypassing network isolation mechanisms

---

*Runtime Isolation provides critical security boundaries that contain MCP tools and prevent them from compromising the host system or accessing unauthorized resources.*