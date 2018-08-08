import unittest

import logging

from . import iputils
from . import ssutils
from . import utils
from . import firewallgen
from . import dockerutils
from .ssutils import (Punctuation, Identifier, Number, String)

logger = logging.getLogger('firewallgen')

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s'

# Change logging LEVEL according to debugging needs.
# Probably better to read this from a config or a launch parameter.
# LEVEL = logging.DEBUG
LEVEL = logging.WARNING

logging.basicConfig(format=FORMAT, level=LEVEL)

CGROUP_LINES_GOOD = """11:pids:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
10:cpuset:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
9:freezer:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
8:perf_event:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
7:memory:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
6:net_prio,net_cls:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
5:blkio:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
4:hugetlb:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
3:cpuacct,cpu:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
2:devices:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
1:name=systemd:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af476dd8a3122b3ad1740b
"""

CGROUP_LINES_BAD = """11:pids:/system.slice/sshd.service
10:cpuset:/
9:freezer:/
8:perf_event:/
7:memory:/system.slice/sshd.service
6:net_prio,net_cls:/
5:blkio:/system.slice/sshd.service
4:hugetlb:/
3:cpuacct,cpu:/system.slice/sshd.service
2:devices:/system.slice/sshd.service
1:name=systemd:/system.slice/sshd.service
"""

SS_OUTPUT = """State       Recv-Q Send-Q                                         Local Address:Port                                                        Peer Address:Port              
LISTEN      0      128                                                10.65.1.0:35357                                                                  *:*                   users:(("httpd",pid=3274,fd=4),("httpd",pid=2789,fd=4),("httpd",pid=2778,fd=4),("httpd",pid=2775,fd=4),("httpd",pid=2774,fd=4),("httpd",pid=2769,fd=4),("httpd",pid=2766,fd=4),("httpd",pid=2761,fd=4),("httpd",pid=2748,fd=4),("httpd",pid=2743,fd=4),("httpd",pid=2656,fd=4))
LISTEN      0      128                                                10.65.0.1:35357                                                                  *:*                   users:(("haproxy",pid=3306,fd=10))
LISTEN      0      128                                                10.65.1.0:9150                                                                   *:*                   users:(("memcached_expor",pid=4049,fd=3))
LISTEN      0      128                                                        *:6783                                                                   *:*                   users:(("alertmanager",pid=4610,fd=5))
LISTEN      0      128                                                10.65.1.0:9696                                                                   *:*                   users:(("neutron-server",pid=10809,fd=12),("neutron-server",pid=10808,fd=12),("neutron-server",pid=10807,fd=12),("neutron-server",pid=10806,fd=12),("neutron-server",pid=10805,fd=12),("neutron-server",pid=10804,fd=12),("neutron-server",pid=10803,fd=12),("neutron-server",pid=10802,fd=12),("neutron-server",pid=10801,fd=12),("neutron-server",pid=10800,fd=12),("neutron-server",pid=10799,fd=12),("neutron-server",pid=10798,fd=12),("neutron-server",pid=3537,fd=12))
LISTEN      0      128                                                10.65.1.0:8000                                                                   *:*                   users:(("heat-api-cfn",pid=8452,fd=4),("heat-api-cfn",pid=8451,fd=4),("heat-api-cfn",pid=8450,fd=4),("heat-api-cfn",pid=8449,fd=4),("heat-api-cfn",pid=8448,fd=4),("heat-api-cfn",pid=3536,fd=4))
LISTEN      0      100                                                10.65.1.0:6080                                                                   *:*                   users:(("nova-novncproxy",pid=3027,fd=4))
LISTEN      0      128                                                10.60.0.1:8000                                                                   *:*                   users:(("haproxy",pid=3306,fd=31))
LISTEN      0      128                                                10.65.0.1:8000                                                                   *:*                   users:(("haproxy",pid=3306,fd=29))
LISTEN      0      128                                                10.60.0.1:9696                                                                   *:*                   users:(("haproxy",pid=3306,fd=23))
LISTEN      0      128                                                10.65.0.1:9696                                                                   *:*                   users:(("haproxy",pid=3306,fd=22))
LISTEN      0      128                                                10.60.0.1:6080                                                                   *:*                   users:(("haproxy",pid=3306,fd=21))
LISTEN      0      128                                                10.65.0.1:6080                                                                   *:*                   users:(("haproxy",pid=3306,fd=17))
LISTEN      0      128                                                10.65.1.0:1984                                                                   *:*                   users:(("haproxy",pid=3306,fd=5))
LISTEN      0      128                                                10.65.1.0:5601                                                                   *:*                   users:(("node",pid=4206,fd=14))
LISTEN      0      128                                                10.60.0.1:5601                                                                   *:*                   users:(("haproxy",pid=3306,fd=41))
LISTEN      0      128                                                10.65.0.1:5601                                                                   *:*                   users:(("haproxy",pid=3306,fd=40))
LISTEN      0      128                                                10.65.1.0:9091                                                                   *:*                   users:(("prometheus",pid=2954,fd=21))
LISTEN      0      128                                                10.65.0.1:9091                                                                   *:*                   users:(("haproxy",pid=3306,fd=43))
LISTEN      0      128                                                10.65.1.0:8004                                                                   *:*                   users:(("heat-api",pid=8461,fd=4),("heat-api",pid=8460,fd=4),("heat-api",pid=8459,fd=4),("heat-api",pid=8458,fd=4),("heat-api",pid=8457,fd=4),("heat-api",pid=4055,fd=4))
LISTEN      0      128                                                10.60.0.1:8004                                                                   *:*                   users:(("haproxy",pid=3306,fd=30))
LISTEN      0      128                                                10.65.0.1:8004                                                                   *:*                   users:(("haproxy",pid=3306,fd=28))
LISTEN      0      128                                                10.65.1.0:9093                                                                   *:*                   users:(("alertmanager",pid=4610,fd=3))
LISTEN      0      128                                                10.60.0.1:9093                                                                   *:*                   users:(("haproxy",pid=3306,fd=47))
LISTEN      0      128                                                10.65.0.1:9093                                                                   *:*                   users:(("haproxy",pid=3306,fd=46))
LISTEN      0      128                                                10.65.1.0:8774                                                                   *:*                   users:(("nova-api",pid=8799,fd=7),("nova-api",pid=8798,fd=7),("nova-api",pid=8797,fd=7),("nova-api",pid=8796,fd=7),("nova-api",pid=8795,fd=7),("nova-api",pid=8782,fd=7),("nova-api",pid=8781,fd=7),("nova-api",pid=8780,fd=7),("nova-api",pid=8779,fd=7),("nova-api",pid=8778,fd=7),("nova-api",pid=2996,fd=7))
LISTEN      0      128                                                10.60.0.1:8774                                                                   *:*                   users:(("haproxy",pid=3306,fd=18))
LISTEN      0      128                                                10.65.0.1:8774                                                                   *:*                   users:(("haproxy",pid=3306,fd=14))
LISTEN      0      128                                                10.65.1.0:8775                                                                   *:*                   users:(("nova-api",pid=8799,fd=8),("nova-api",pid=8798,fd=8),("nova-api",pid=8797,fd=8),("nova-api",pid=8796,fd=8),("nova-api",pid=8795,fd=8),("nova-api",pid=2996,fd=8))
LISTEN      0      128                                                10.65.1.0:9191                                                                   *:*                   users:(("glance-registry",pid=8312,fd=4),("glance-registry",pid=8311,fd=4),("glance-registry",pid=8310,fd=4),("glance-registry",pid=8309,fd=4),("glance-registry",pid=8308,fd=4),("glance-registry",pid=3379,fd=4))
LISTEN      0      128                                                10.60.0.1:8775                                                                   *:*                   users:(("haproxy",pid=3306,fd=19))
LISTEN      0      128                                                10.65.0.1:8775                                                                   *:*                   users:(("haproxy",pid=3306,fd=15))
LISTEN      0      128                                                10.65.0.1:9191                                                                   *:*                   users:(("haproxy",pid=3306,fd=11))
LISTEN      0      128                                                10.65.1.0:5672                                                                   *:*                   users:(("beam.smp",pid=6375,fd=54))
LISTEN      0      128                                                10.65.1.0:25672                                                                  *:*                   users:(("beam.smp",pid=6375,fd=45))
LISTEN      0      128                                                10.65.1.0:5000                                                                   *:*                   users:(("httpd",pid=3274,fd=3),("httpd",pid=2789,fd=3),("httpd",pid=2778,fd=3),("httpd",pid=2775,fd=3),("httpd",pid=2774,fd=3),("httpd",pid=2769,fd=3),("httpd",pid=2766,fd=3),("httpd",pid=2761,fd=3),("httpd",pid=2748,fd=3),("httpd",pid=2743,fd=3),("httpd",pid=2656,fd=3))
LISTEN      0      128                                                10.65.1.0:8776                                                                   *:*                   users:(("httpd",pid=94355,fd=3),("httpd",pid=92918,fd=3),("httpd",pid=92674,fd=3),("httpd",pid=5557,fd=3),("httpd",pid=5556,fd=3),("httpd",pid=5555,fd=3),("httpd",pid=5554,fd=3),("httpd",pid=5553,fd=3),("httpd",pid=3083,fd=3))
LISTEN      0      128                                                10.60.0.1:8776                                                                   *:*                   users:(("haproxy",pid=3306,fd=27))
LISTEN      0      128                                                10.65.0.1:8776                                                                   *:*                   users:(("haproxy",pid=3306,fd=26))
LISTEN      0      128                                                10.60.0.1:5000                                                                   *:*                   users:(("haproxy",pid=3306,fd=9))
LISTEN      0      128                                                10.65.0.1:5000                                                                   *:*                   users:(("haproxy",pid=3306,fd=8))
LISTEN      0      50                                                 127.0.0.1:6633                                                                   *:*                   users:(("neutron-openvsw",pid=3347,fd=5))
LISTEN      0      128                                                10.65.1.0:3306                                                                   *:*                   users:(("mysqld",pid=6736,fd=30))
LISTEN      0      128                                                10.65.0.1:3306                                                                   *:*                   users:(("haproxy",pid=3306,fd=44))
LISTEN      0      128                                                10.65.1.0:2379                                                                   *:*                   users:(("etcd",pid=5335,fd=5))
LISTEN      0      128                                                10.65.1.0:11211                                                                  *:*                   users:(("memcached",pid=4093,fd=26))
LISTEN      0      128                                                10.65.0.1:11211                                                                  *:*                   users:(("haproxy",pid=3306,fd=45))
LISTEN      0      128                                                10.65.1.0:9292                                                                   *:*                   users:(("glance-api",pid=8751,fd=4),("glance-api",pid=8750,fd=4),("glance-api",pid=8749,fd=4),("glance-api",pid=8748,fd=4),("glance-api",pid=8747,fd=4),("glance-api",pid=5345,fd=4))
LISTEN      0      128                                                10.65.1.0:2380                                                                   *:*                   users:(("etcd",pid=5335,fd=3))
LISTEN      0      128                                                10.65.1.0:9100                                                                   *:*                   users:(("node_exporter",pid=3227,fd=3))
LISTEN      0      128                                                10.65.1.0:8780                                                                   *:*                   users:(("httpd",pid=92842,fd=5),("httpd",pid=60367,fd=5),("httpd",pid=10539,fd=5),("httpd",pid=9437,fd=5),("httpd",pid=9301,fd=5),("httpd",pid=8924,fd=5),("httpd",pid=3703,fd=5),("httpd",pid=3702,fd=5),("httpd",pid=3701,fd=5),("httpd",pid=3700,fd=5),("httpd",pid=2966,fd=5))
LISTEN      0      128                                                10.60.0.1:8780                                                                   *:*                   users:(("haproxy",pid=3306,fd=20))
LISTEN      0      128                                                10.65.0.1:8780                                                                   *:*                   users:(("haproxy",pid=3306,fd=16))
LISTEN      0      128                                                10.60.0.1:9292                                                                   *:*                   users:(("haproxy",pid=3306,fd=13))
LISTEN      0      128                                                10.65.0.1:9292                                                                   *:*                   users:(("haproxy",pid=3306,fd=12))
LISTEN      0      128                                                10.65.1.0:9101                                                                   *:*                   users:(("haproxy_exporte",pid=4163,fd=3))
LISTEN      0      128                                                        *:111                                                                    *:*                   users:(("rpcbind",pid=644,fd=8))
LISTEN      0      128                                                10.65.1.0:80                                                                     *:*                   users:(("httpd",pid=55123,fd=3),("httpd",pid=55122,fd=3),("httpd",pid=55121,fd=3),("httpd",pid=55120,fd=3),("httpd",pid=55098,fd=3),("httpd",pid=54904,fd=3),("httpd",pid=27347,fd=3),("httpd",pid=27346,fd=3),("httpd",pid=27345,fd=3),("httpd",pid=27344,fd=3),("httpd",pid=4998,fd=3))
LISTEN      0      128                                                        *:8080                                                                   *:*                   users:(("nginx",pid=9170,fd=6),("nginx",pid=8875,fd=6))
LISTEN      0      128                                                10.65.1.0:9104                                                                   *:*                   users:(("mysqld_exporter",pid=5586,fd=3))
LISTEN      0      10                                                 127.0.0.1:6640                                                                   *:*                   users:(("ovsdb-server",pid=4260,fd=12))
LISTEN      0      128                                                10.65.0.1:9200                                                                   *:*                   users:(("haproxy",pid=3306,fd=42))
LISTEN      0      128                                                10.60.0.1:80                                                                     *:*                   users:(("haproxy",pid=3306,fd=25))
LISTEN      0      128                                                10.65.0.1:80                                                                     *:*                   users:(("haproxy",pid=3306,fd=24))
LISTEN      0      128                                                10.65.1.0:6385                                                                   *:*                   users:(("ironic-api",pid=9330,fd=6),("ironic-api",pid=9329,fd=6),("ironic-api",pid=9328,fd=6),("ironic-api",pid=9327,fd=6),("ironic-api",pid=9326,fd=6),("ironic-api",pid=5329,fd=6))
LISTEN      0      128                                                        *:4369                                                                   *:*                   users:(("epmd",pid=5814,fd=3))
LISTEN      0      128                                                10.60.0.1:6385                                                                   *:*                   users:(("haproxy",pid=3306,fd=36))
LISTEN      0      128                                                10.65.0.1:6385                                                                   *:*                   users:(("haproxy",pid=3306,fd=34))
LISTEN      0      128                                                10.65.1.0:8786                                                                   *:*                   users:(("manila-api",pid=10009,fd=7),("manila-api",pid=10008,fd=7),("manila-api",pid=10007,fd=7),("manila-api",pid=10006,fd=7),("manila-api",pid=10005,fd=7),("manila-api",pid=5036,fd=7))
LISTEN      0      128                                                10.60.0.1:8786                                                                   *:*                   users:(("haproxy",pid=3306,fd=39))
LISTEN      0      128                                                10.65.0.1:8786                                                                   *:*                   users:(("haproxy",pid=3306,fd=38))
LISTEN      0      128                                                        *:22                                                                     *:*                   users:(("sshd",pid=2468,fd=3))
LISTEN      0      128                                                10.65.1.0:4567                                                                   *:*                   users:(("mysqld",pid=6736,fd=11))
LISTEN      0      128                                                10.65.1.0:8023                                                                   *:*                   users:(("sshd",pid=5288,fd=3))
LISTEN      0      128                                                10.65.1.0:15672                                                                  *:*                   users:(("beam.smp",pid=6375,fd=56))
LISTEN      0      128                                                10.65.1.0:3000                                                                   *:*                   users:(("grafana-server",pid=7064,fd=7))
LISTEN      0      128                                                10.60.0.1:3000                                                                   *:*                   users:(("haproxy",pid=3306,fd=33))
LISTEN      0      128                                                10.65.0.1:3000                                                                   *:*                   users:(("haproxy",pid=3306,fd=32))
LISTEN      0      128                                                10.65.0.1:15672                                                                  *:*                   users:(("haproxy",pid=3306,fd=7))
LISTEN      0      128                                                10.65.1.0:8089                                                                   *:*                   users:(("httpd",pid=59115,fd=3),("httpd",pid=6868,fd=3),("httpd",pid=6867,fd=3),("httpd",pid=6866,fd=3),("httpd",pid=6865,fd=3),("httpd",pid=6864,fd=3),("httpd",pid=4959,fd=3))
LISTEN      0      100                                                127.0.0.1:25                                                                     *:*                   users:(("master",pid=2448,fd=13))
LISTEN      0      128                                                10.65.1.0:5050                                                                   *:*                   users:(("ironic-inspecto",pid=17689,fd=7))
LISTEN      0      128                                                10.60.0.1:5050                                                                   *:*                   users:(("haproxy",pid=3306,fd=37))
LISTEN      0      128                                                10.65.0.1:5050                                                                   *:*                   users:(("haproxy",pid=3306,fd=35))
"""

LSHW_OUT = """                                                                
{
  "id" : "juno",
  "class" : "system",
  "claimed" : true,
  "description" : "Computer",
  "width" : 4294967295,
  "capabilities" : {
    "smp" : "Symmetric Multi-Processing",
    "vsyscall32" : "32-bit processes"
  },
  "children" : [
    {
      "id" : "core",
      "class" : "bus",
      "claimed" : true,
      "description" : "Motherboard",
      "physid" : "0",
      "children" : [
        {
          "id" : "memory",
          "class" : "memory",
          "claimed" : true,
          "description" : "System memory",
          "physid" : "0",
          "units" : "bytes",
          "size" : 25085755392
        },
        {
          "id" : "cpu",
          "class" : "processor",
          "claimed" : true,
          "product" : "Intel(R) Core(TM) i5-8400H CPU @ 2.50GHz",
          "vendor" : "Intel Corp.",
          "physid" : "1",
          "businfo" : "cpu@0",
          "units" : "Hz",
          "size" : 2579225000,
          "capacity" : 4200000000,
          "width" : 64,
          "capabilities" : {
            "fpu" : "mathematical co-processor",
            "fpu_exception" : "FPU exceptions reporting",
            "wp" : true,
            "vme" : "virtual mode extensions",
            "de" : "debugging extensions",
            "pse" : "page size extensions",
            "tsc" : "time stamp counter",
            "msr" : "model-specific registers",
            "pae" : "4GB+ memory addressing (Physical Address Extension)",
            "mce" : "machine check exceptions",
            "cx8" : "compare and exchange 8-byte",
            "apic" : "on-chip advanced programmable interrupt controller (APIC)",
            "sep" : "fast system calls",
            "mtrr" : "memory type range registers",
            "pge" : "page global enable",
            "mca" : "machine check architecture",
            "cmov" : "conditional move instruction",
            "pat" : "page attribute table",
            "pse36" : "36-bit page size extensions",
            "clflush" : true,
            "dts" : "debug trace and EMON store MSRs",
            "acpi" : "thermal control (ACPI)",
            "mmx" : "multimedia extensions (MMX)",
            "fxsr" : "fast floating point save/restore",
            "sse" : "streaming SIMD extensions (SSE)",
            "sse2" : "streaming SIMD extensions (SSE2)",
            "ss" : "self-snoop",
            "ht" : "HyperThreading",
            "tm" : "thermal interrupt and status",
            "pbe" : "pending break event",
            "syscall" : "fast system calls",
            "nx" : "no-execute bit (NX)",
            "pdpe1gb" : true,
            "rdtscp" : true,
            "x86-64" : "64bits extensions (x86-64)",
            "constant_tsc" : true,
            "art" : true,
            "arch_perfmon" : true,
            "pebs" : true,
            "bts" : true,
            "rep_good" : true,
            "nopl" : true,
            "xtopology" : true,
            "nonstop_tsc" : true,
            "cpuid" : true,
            "aperfmperf" : true,
            "tsc_known_freq" : true,
            "pni" : true,
            "pclmulqdq" : true,
            "dtes64" : true,
            "monitor" : true,
            "ds_cpl" : true,
            "vmx" : true,
            "smx" : true,
            "est" : true,
            "tm2" : true,
            "ssse3" : true,
            "sdbg" : true,
            "fma" : true,
            "cx16" : true,
            "xtpr" : true,
            "pdcm" : true,
            "pcid" : true,
            "sse4_1" : true,
            "sse4_2" : true,
            "x2apic" : true,
            "movbe" : true,
            "popcnt" : true,
            "tsc_deadline_timer" : true,
            "aes" : true,
            "xsave" : true,
            "avx" : true,
            "f16c" : true,
            "rdrand" : true,
            "lahf_lm" : true,
            "abm" : true,
            "3dnowprefetch" : true,
            "cpuid_fault" : true,
            "epb" : true,
            "invpcid_single" : true,
            "pti" : true,
            "ibrs" : true,
            "ibpb" : true,
            "stibp" : true,
            "tpr_shadow" : true,
            "vnmi" : true,
            "flexpriority" : true,
            "ept" : true,
            "vpid" : true,
            "fsgsbase" : true,
            "tsc_adjust" : true,
            "bmi1" : true,
            "hle" : true,
            "avx2" : true,
            "smep" : true,
            "bmi2" : true,
            "erms" : true,
            "invpcid" : true,
            "rtm" : true,
            "mpx" : true,
            "rdseed" : true,
            "adx" : true,
            "smap" : true,
            "clflushopt" : true,
            "intel_pt" : true,
            "xsaveopt" : true,
            "xsavec" : true,
            "xgetbv1" : true,
            "xsaves" : true,
            "dtherm" : true,
            "ida" : true,
            "arat" : true,
            "pln" : true,
            "pts" : true,
            "hwp" : true,
            "hwp_notify" : true,
            "hwp_act_window" : true,
            "hwp_epp" : true,
            "cpufreq" : "CPU Frequency scaling"
          }
        },
        {
          "id" : "pci",
          "class" : "bridge",
          "claimed" : true,
          "handle" : "PCIBUS:0000:00",
          "description" : "Host bridge",
          "product" : "Intel Corporation",
          "vendor" : "Intel Corporation",
          "physid" : "100",
          "businfo" : "pci@0000:00:00.0",
          "version" : "07",
          "width" : 32,
          "clock" : 33000000,
          "children" : [
            {
              "id" : "display",
              "class" : "display",
              "claimed" : true,
              "handle" : "PCI:0000:00:02.0",
              "description" : "VGA compatible controller",
              "product" : "Intel Corporation",
              "vendor" : "Intel Corporation",
              "physid" : "2",
              "businfo" : "pci@0000:00:02.0",
              "version" : "00",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "i915",
                "latency" : "0"
              },
              "capabilities" : {
                "vga_controller" : true,
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing",
                "rom" : "extension ROM"
              }
            },
            {
              "id" : "generic:0",
              "class" : "generic",
              "claimed" : true,
              "handle" : "PCI:0000:00:04.0",
              "description" : "Signal processing controller",
              "product" : "Xeon E3-1200 v5/E3-1500 v5/6th Gen Core Processor Thermal Subsystem",
              "vendor" : "Intel Corporation",
              "physid" : "4",
              "businfo" : "pci@0000:00:04.0",
              "version" : "07",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "proc_thermal",
                "latency" : "0"
              },
              "capabilities" : {
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "generic:1",
              "class" : "generic",
              "handle" : "PCI:0000:00:08.0",
              "description" : "System peripheral",
              "product" : "Xeon E3-1200 v5/v6 / E3-1500 v5 / 6th/7th Gen Core Processor Gaussian Mixture Model",
              "vendor" : "Intel Corporation",
              "physid" : "8",
              "businfo" : "pci@0000:00:08.0",
              "version" : "00",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "latency" : "0"
              },
              "capabilities" : {
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "generic:2",
              "class" : "generic",
              "claimed" : true,
              "handle" : "PCI:0000:00:12.0",
              "description" : "Signal processing controller",
              "product" : "Cannon Lake PCH Thermal Controller",
              "vendor" : "Intel Corporation",
              "physid" : "12",
              "businfo" : "pci@0000:00:12.0",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "intel_pch_thermal",
                "latency" : "0"
              },
              "capabilities" : {
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "usb",
              "class" : "bus",
              "claimed" : true,
              "handle" : "PCI:0000:00:14.0",
              "description" : "USB controller",
              "product" : "Cannon Lake PCH USB 3.1 xHCI Host Controller",
              "vendor" : "Intel Corporation",
              "physid" : "14",
              "businfo" : "pci@0000:00:14.0",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "xhci_hcd",
                "latency" : "0"
              },
              "capabilities" : {
                "xhci" : true,
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "memory",
              "class" : "memory",
              "handle" : "PCI:0000:00:14.2",
              "description" : "RAM memory",
              "product" : "Cannon Lake PCH Shared SRAM",
              "vendor" : "Intel Corporation",
              "physid" : "14.2",
              "businfo" : "pci@0000:00:14.2",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "latency" : "0"
              },
              "capabilities" : {
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "network:0",
              "class" : "network",
              "claimed" : true,
              "handle" : "PCI:0000:00:14.3",
              "description" : "Wireless interface",
              "product" : "Wireless-AC 9560 [Jefferson Peak]",
              "vendor" : "Intel Corporation",
              "physid" : "14.3",
              "businfo" : "pci@0000:00:14.3",
              "logicalname" : "wlo1",
              "version" : "10",
              "serial" : "94:b8:6d:0d:0b:06",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "broadcast" : "yes",
                "driver" : "iwlwifi",
                "driverversion" : "4.17.8-1-ARCH",
                "firmware" : "38.c0e03d94.0",
                "ip" : "192.168.1.85",
                "latency" : "0",
                "link" : "yes",
                "multicast" : "yes",
                "wireless" : "IEEE 802.11"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing",
                "ethernet" : true,
                "physical" : "Physical interface",
                "wireless" : "Wireless-LAN"
              }
            },
            {
              "id" : "serial:0",
              "class" : "bus",
              "claimed" : true,
              "handle" : "PCI:0000:00:15.0",
              "description" : "Serial bus controller",
              "product" : "Intel Corporation",
              "vendor" : "Intel Corporation",
              "physid" : "15",
              "businfo" : "pci@0000:00:15.0",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "intel-lpss",
                "latency" : "0"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "serial:1",
              "class" : "bus",
              "claimed" : true,
              "handle" : "PCI:0000:00:15.1",
              "description" : "Serial bus controller",
              "product" : "Intel Corporation",
              "vendor" : "Intel Corporation",
              "physid" : "15.1",
              "businfo" : "pci@0000:00:15.1",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "intel-lpss",
                "latency" : "0"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "communication",
              "class" : "communication",
              "claimed" : true,
              "handle" : "PCI:0000:00:16.0",
              "description" : "Communication controller",
              "product" : "Cannon Lake PCH HECI Controller",
              "vendor" : "Intel Corporation",
              "physid" : "16",
              "businfo" : "pci@0000:00:16.0",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "mei_me",
                "latency" : "0"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "storage",
              "class" : "storage",
              "claimed" : true,
              "handle" : "PCI:0000:00:17.0",
              "description" : "SATA controller",
              "product" : "Intel Corporation",
              "vendor" : "Intel Corporation",
              "physid" : "17",
              "businfo" : "pci@0000:00:17.0",
              "version" : "10",
              "width" : 32,
              "clock" : 66000000,
              "configuration" : {
                "driver" : "ahci",
                "latency" : "0"
              },
              "capabilities" : {
                "storage" : true,
                "ahci_1.0" : true,
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "isa",
              "class" : "bridge",
              "claimed" : true,
              "handle" : "PCI:0000:00:1f.0",
              "description" : "ISA bridge",
              "product" : "Intel Corporation",
              "vendor" : "Intel Corporation",
              "physid" : "1f",
              "businfo" : "pci@0000:00:1f.0",
              "version" : "10",
              "width" : 32,
              "clock" : 33000000,
              "configuration" : {
                "latency" : "0"
              },
              "capabilities" : {
                "isa" : true,
                "bus_master" : "bus mastering"
              }
            },
            {
              "id" : "multimedia",
              "class" : "multimedia",
              "claimed" : true,
              "handle" : "PCI:0000:00:1f.3",
              "description" : "Audio device",
              "product" : "Cannon Lake PCH cAVS",
              "vendor" : "Intel Corporation",
              "physid" : "1f.3",
              "businfo" : "pci@0000:00:1f.3",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "snd_hda_intel",
                "latency" : "32"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing"
              }
            },
            {
              "id" : "serial:2",
              "class" : "bus",
              "claimed" : true,
              "handle" : "PCI:0000:00:1f.4",
              "description" : "SMBus",
              "product" : "Cannon Lake PCH SMBus Controller",
              "vendor" : "Intel Corporation",
              "physid" : "1f.4",
              "businfo" : "pci@0000:00:1f.4",
              "version" : "10",
              "width" : 64,
              "clock" : 33000000,
              "configuration" : {
                "driver" : "i801_smbus",
                "latency" : "0"
              }
            },
            {
              "id" : "serial:3",
              "class" : "bus",
              "handle" : "PCI:0000:00:1f.5",
              "description" : "Serial bus controller",
              "product" : "Cannon Lake PCH SPI Controller",
              "vendor" : "Intel Corporation",
              "physid" : "1f.5",
              "businfo" : "pci@0000:00:1f.5",
              "version" : "10",
              "width" : 32,
              "clock" : 33000000,
              "configuration" : {
                "latency" : "0"
              }
            },
            {
              "id" : "network:1",
              "class" : "network",
              "disabled" : true,
              "claimed" : true,
              "handle" : "PCI:0000:00:1f.6",
              "description" : "Ethernet interface",
              "product" : "Ethernet Connection (7) I219-LM",
              "vendor" : "Intel Corporation",
              "physid" : "1f.6",
              "businfo" : "pci@0000:00:1f.6",
              "logicalname" : "eno2",
              "version" : "10",
              "serial" : "10:65:30:4f:ec:ab",
              "units" : "bit/s",
              "capacity" : 1000000000,
              "width" : 32,
              "clock" : 33000000,
              "configuration" : {
                "autonegotiation" : "on",
                "broadcast" : "yes",
                "driver" : "e1000e",
                "driverversion" : "3.2.6-k",
                "firmware" : "0.5-4",
                "latency" : "0",
                "link" : "no",
                "multicast" : "yes",
                "port" : "twisted pair"
              },
              "capabilities" : {
                "bus_master" : "bus mastering",
                "cap_list" : "PCI capabilities listing",
                "ethernet" : true,
                "physical" : "Physical interface",
                "tp" : "twisted pair",
                "10bt" : "10Mbit/s",
                "10bt-fd" : "10Mbit/s (full duplex)",
                "100bt" : "100Mbit/s",
                "100bt-fd" : "100Mbit/s (full duplex)",
                "1000bt-fd" : "1Gbit/s (full duplex)",
                "autonegotiation" : "Auto-negotiation"
              }
            }
          ]
        }
      ]
    },
    {
      "id" : "network:0",
      "class" : "network",
      "claimed" : true,
      "description" : "Ethernet interface",
      "physid" : "1",
      "logicalname" : "virbr0",
      "serial" : "52:54:00:d0:4e:0d",
      "configuration" : {
        "broadcast" : "yes",
        "driver" : "bridge",
        "driverversion" : "2.3",
        "firmware" : "N/A",
        "ip" : "192.168.122.1",
        "link" : "yes",
        "multicast" : "yes"
      },
      "capabilities" : {
        "ethernet" : true,
        "physical" : "Physical interface"
      }
    },
    {
      "id" : "network:1",
      "class" : "network",
      "disabled" : true,
      "claimed" : true,
      "description" : "Ethernet interface",
      "physid" : "2",
      "logicalname" : "virbr0-nic",
      "serial" : "52:54:00:d0:4e:0d",
      "units" : "bit/s",
      "size" : 10000000,
      "configuration" : {
        "autonegotiation" : "off",
        "broadcast" : "yes",
        "driver" : "tun",
        "driverversion" : "1.6",
        "duplex" : "full",
        "link" : "no",
        "multicast" : "yes",
        "port" : "twisted pair",
        "speed" : "10Mbit/s"
      },
      "capabilities" : {
        "ethernet" : true,
        "physical" : "Physical interface"
      }
    },
    {
      "id" : "network:2",
      "class" : "network",
      "claimed" : true,
      "description" : "Ethernet interface",
      "physid" : "3",
      "logicalname" : "vnet0",
      "serial" : "fe:54:00:57:4d:f2",
      "units" : "bit/s",
      "size" : 10000000,
      "configuration" : {
        "autonegotiation" : "off",
        "broadcast" : "yes",
        "driver" : "tun",
        "driverversion" : "1.6",
        "duplex" : "full",
        "link" : "yes",
        "multicast" : "yes",
        "port" : "twisted pair",
        "speed" : "10Mbit/s"
      },
      "capabilities" : {
        "ethernet" : true,
        "physical" : "Physical interface"
      }
    }
  ]
}

"""


class FakeLSHWRunner(utils.CmdRunner):
    def check_output(self, *_, **__):
        return LSHW_OUT


class IPUtilsTest(unittest.TestCase):
    def test_parse_port(self):
        res = iputils.do_parse_port("10.1.1.8:8001")
        self.assertEqual(('10.1.1.8', 8001), res)
        res = iputils.do_parse_port("*:8001")
        self.assertEqual(('*', 8001), res)
        res = iputils.do_parse_port("::1:25")
        self.assertEqual(('::1', 25), res)

    def test_lookup_interface(self):
        map = iputils.get_ip_to_interface_map(FakeLSHWRunner())
        self.assertEqual(map['192.168.1.85'], 'wlo1')


class DockerUtilsTest(unittest.TestCase):
    def test_process_cgroup_line_good(self):
        good = ("11:pids:/docker/cc0d36ee5866b01475012e2d2aff051ac169c12963af4"
                "76dd8a3122b3ad1740b")
        id_ = dockerutils._process_cgroup_line(
            good)
        self.assertEqual(id_, "cc0d36ee5866b01475012e2d2aff051ac169c12963af47"
                              "6dd8a3122b3ad1740b")

    def test_process_cgroup_line_bad(self):
        input = "10:cpuset:/"
        id_ = dockerutils._process_cgroup_line(
            input)
        self.assertEqual(id_, None)

    def test_cgroup_lines(self):
        id_ = dockerutils._cgroup_lines_to_container_id(
            CGROUP_LINES_GOOD.splitlines())
        self.assertEqual(id_, "cc0d36ee5866b01475012e2d2aff051ac169c12963af47"
                              "6dd8a3122b3ad1740b")

    def test_cgroup_lines_bad(self):
        id_ = dockerutils._cgroup_lines_to_container_id(
            CGROUP_LINES_BAD.splitlines())
        self.assertEqual(id_, None)

    def test_clean_container_name_docker_output(self):
        input_ = "/prometheus_cadvisor"
        output = dockerutils._clean_container_name_docker_output(
            input_)
        self.assertEqual("prometheus_cadvisor", output)


class SSUtilsTest(unittest.TestCase):
    TOKENS = [Identifier(data='users'), Punctuation(data=':'),
              Punctuation(data='('), Punctuation(data='('),
              String(data='haproxy'), Punctuation(data=','),
              Identifier(data='pid'), Punctuation(data='='),
              Number(data='3306'), Punctuation(data=','),
              Identifier(data='fd'), Punctuation(data='='), Number(data='30'),
              Punctuation(data=')'), Punctuation(data=')')]

    def test_parse_ss_output(self):
        print(ssutils.parse_ss_output(SS_OUTPUT))

    def test_tokenize(self):
        res = [Identifier(data='users'), Punctuation(data=':'),
               Punctuation(data='('), Punctuation(data='('),
               String(data='haproxy'), Punctuation(data=','),
               Identifier(data='pid'), Punctuation(data='='),
               Number(data='3306'), Punctuation(data=','),
               Identifier(data='fd'), Punctuation(data='='), Number(data='30'),
               Punctuation(data=')'), Punctuation(data=')')]
        tokens = ssutils.tokenize_extras('users:(("haproxy",pid=3306,fd=30))')
        self.assertEqual(res, tokens)

    def test_parse(self):
        # Should parse without error
        tokens = self.TOKENS
        parser = ssutils.AstGen(tokens)
        parser.get_ast()

    def test_visit(self):
        tokens = self.TOKENS
        parser = ssutils.AstGen(tokens)
        ast = parser.get_ast()
        visitor = ssutils.Reformatter()
        ast.accept(visitor)
        self.assertEqual(
            '"users": [{"name": "haproxy", "pid": 3306,"fd": 30}]',
            visitor.output)

    def test_parse_list(self):
        tokens = ssutils.tokenize_extras(
            '(("haproxy",pid=3306,fd=30), ("haproxy2",pid=33062,fd=302))')
        parser = ssutils.AstGen(tokens)
        parser.parse_list()


def fake_pid_to_docker(pid, **kwargs):
    return "docker-{}".format(pid)


class FakeCollector(firewallgen.TCPDataCollector):
    def get_ss_output(self):
        return iter(SS_OUTPUT.splitlines())


class FirewallGen(unittest.TestCase):
    def test_opensockets(self):
        result = self.get_open_sockets()

    def get_open_sockets(self):
        map = {
            '10.65.1.0': 'eth1',
            '10.65.0.1': 'eth2',
            '10.60.0.1': 'eth3',
            '127.0.0.1': 'lo'
        }
        result = firewallgen.collect_open_sockets(FakeCollector(), map,
                                                  docker_hinter=fake_pid_to_docker)
        return result

    def test_gen_conf(self):
        sockets = self.get_open_sockets()
        print(firewallgen.gen_firewall(sockets))

if __name__ == '__main__':
    unittest.main()
