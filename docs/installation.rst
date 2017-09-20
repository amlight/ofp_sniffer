Installation
============

ofp_sniffer was written in Python3.6. It is recommended that you either setup Python 3.6 on a virtualenv or use the Docker image with the provided docker-compose.yml file. Also, since ofp_sniffer relies on `pcapy` to leverage lipcap, it is necessary to install `libpcap-dev` package on your OS (if you decide to stick with the virtualenv approach), Docker has this dependecy packaged.

First of all, clone this repository:

.. code:: shell

   git clone https://github.com/amlight/ofp_sniffer.git
   cd ofp_sniffer

virtualenv
----------

For Ubuntu 16.04:

.. code:: shell

   sudo add-apt-repository ppa:jonathonf/python-3.6
   sudo apt update && apt install git libpython3.6-dev python3.6 python3.6-venv
   python3.6 -m venv ofp_s
   source ofp_s/bin/activate
   pip3.6 install -r docs/requirements.txt

Run:

.. code:: shell

   sudo python3.6 ofp_sniffer.py


Docker
------

If you like to just pull ofp_sniffer without influxdb and grafana:

.. code:: shell

   docker pull amlight/ofp_sniffer:1.1

.. note::

   This docker image will be uploaded on docker hub after publishing this documentation on readthedocs

   .. docker run -it --rm amlight/ofp_sniffer:1.1 /opt/ofp_sniffer/python3.6

Docker Compose
--------------

Currently, this project is shipped with a docker-compose file, which is supposed to provide you a complete OpenFlow enviroment, just so you can easily test and experiment `ofp_sniffer`. The following services are present:

- `ofp_sniffer`
- `kytos`, an SDN Platform, that is being used as an OpenFlow controller
- `mininet`, used with a simple topology just to generate some OpenFlow messages to kytos
- `influxdb`
- `grafana`

To spin up all containers:

.. code:: shell

   docker-compose up -d

Currently, you have to manually starts some parameters of mininet and kytos. On kytos:

.. code:: shell

  docker exec -it ofpsniffer_kytos_1 /bin/bash -l
  kytosd -f

On mininet:

.. code:: shell

  docker exec -it ofpsniffer_mininet_1 /bin/bash -l
  mn --clean; mn --controller=remote,ip=127.0.0.1,port=6633 --topo=linear,4 --switch=ovsk,protocols=OpenFlow10 --mac

.. note::

    Both kytos and mininet entrypoint will be automated in a future release.

If you are running running Docker-ce you can inspect docker logs. For example, to check what `ofp_sniffer` is sending to standard output:

.. code:: shell

   ❯ docker logs ofpsniffer_ofp_sniffer_1
    Sniffing device lo

If the other services specified in the docker compose file are runing properly, you should start seeing some OpenFlow messages:

.. code:: shell

    ❯ docker logs ofpsniffer_ofp_sniffer_1
    Sniffing device lo
    Packet #820 - 2017-09-20 14:26:00.516570 127.0.0.1:51920 -> 127.0.0.1:6633 Size: 74 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 8  XID: 1

    Packet #825 - 2017-09-20 14:26:00.517270 127.0.0.1:51922 -> 127.0.0.1:6633 Size: 74 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 8  XID: 2

    Packet #830 - 2017-09-20 14:26:00.517740 127.0.0.1:51924 -> 127.0.0.1:6633 Size: 74 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 8  XID: 3

    Packet #835 - 2017-09-20 14:26:00.518190 127.0.0.1:51926 -> 127.0.0.1:6633 Size: 74 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 8  XID: 4

    Packet #837 - 2017-09-20 14:26:00.707980 127.0.0.1:6633 -> 127.0.0.1:51920 Size: 82 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 16  XID: 0

    Packet #839 - 2017-09-20 14:26:00.808760 127.0.0.1:6633 -> 127.0.0.1:51922 Size: 82 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 16  XID: 0

    Packet #841 - 2017-09-20 14:26:01.037620 127.0.0.1:6633 -> 127.0.0.1:51924 Size: 82 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 16  XID: 0

    Packet #843 - 2017-09-20 14:26:01.159760 127.0.0.1:6633 -> 127.0.0.1:51926 Size: 82 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_HELLO(0) Length: 16  XID: 0

    Packet #845 - 2017-09-20 14:26:01.573010 127.0.0.1:6633 -> 127.0.0.1:51924 Size: 74 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_FEATURES_REQUEST(5) Length: 8  XID: 2498044215

    Packet #847 - 2017-09-20 14:26:01.575990 127.0.0.1(sw3):51924 -> 127.0.0.1:6633 Size: 242 Bytes
    OpenFlow Version: 1.0(1) Type: OFPT_FEATURES_REPLY(6) Length: 176  XID: 2498044215
    FeatureRes - datapath_id: 00:00:00:00:00:00:00:03 n_buffers: 256 n_tables: 254, pad: 000
    FeatureRes - Capabilities: FLOW_STATS(0x1) TABLE_STATS(0x2) PORT_STATS(0x4) QUEUE_STATS(0x40) ARP_MATCH_IP(0x80)
    FeatureRes - Actions: OUTPUT(0x1) SET_VLAN_VID(0x2) SET_VLAN_PCP(0x4) STRIP_VLAN(0x8) SET_DL_SRC(0x10) SET_DL_DST(0x20) SET_NW_SRC(0x40) SET_NW_DST(0x80) SET_NW_TOS(0x100) SET_TP_SRC(0x200) SET_TP_DST(0x400) ENQUEUE(0x800)
    Port_id: 65534 - hw_addr: c2:3b:09:09:47:41 name: s3
    Port_id: 65534 - config: PortDown(0x01)
    Port_id: 65534 - state: LinkDown(0x1)
    Port_id: 65534 - curr: 0
    Port_id: 65534 - advertised: 0
    Port_id: 65534 - supported: 0
    Port_id: 65534 - peer: 0
    Port_id: 2 - hw_addr: 5a:2a:78:60:8d:e4 name: s3-eth2
    Port_id: 2 - config: 0
    Port_id: 2 - state: 0
    Port_id: 2 - curr: 10GB_FD(0x40) Copper(0x80)
    Port_id: 2 - advertised: 0
    Port_id: 2 - supported: 0
    Port_id: 2 - peer: 0
    Port_id: 3 - hw_addr: c2:28:7d:30:4b:5a name: s3-eth3
    Port_id: 3 - config: 0
    Port_id: 3 - state: 0
    Port_id: 3 - curr: 10GB_FD(0x40) Copper(0x80)
    Port_id: 3 - advertised: 0
    Port_id: 3 - supported: 0
    Port_id: 3 - peer: 0



