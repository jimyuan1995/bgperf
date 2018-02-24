# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base import *
import json


class MIRAGE_ST(Container):
    CONTAINER_NAME = None
    GUEST_DIR = '/root/config'

    def __init__(self, host_dir, conf, image='bgperf/mirage_st'):
        super(MIRAGE_ST, self).__init__(self.CONTAINER_NAME, image, host_dir, self.GUEST_DIR, conf)

    def gen_host_config(self):
        host_config = dckr.create_host_config(
            binds=[
                '{0}:{1}'.format(os.path.abspath(self.host_dir), self.guest_dir),
                '/Users/YUAN/Desktop/:/home/opam/host:ro'
            ],
            privileged=True,
            network_mode='bridge',
            cap_add=['NET_ADMIN']
        )
        return host_config

    @classmethod
    def build_image(cls, force=False, tag='bgperf/mirage_st', checkout='bgperf', nocache=False):
        cls.dockerfile = '''
FROM mirage-bgp-spacetime-base:latest

WORKDIR /root

COPY --chown=root:root mrt-format mrt-format
COPY --chown=root:root Bgp4 Mirage-BGP

RUN cd Mirage-BGP/src/bgpd \
&& eval `opam config env` \
&& mirage configure -t unix --net socket \
&& make depend

RUN cd Mirage-BGP/src/bgpd \
&& eval `opam config env` \
&& make
'''.format(checkout)

        def insert_after_from(dockerfile, line):
            lines = dockerfile.split('\n')
            i = -1
            for idx, l in enumerate(lines):
                elems = [e.strip() for e in l.split()]
                if len(elems) > 0 and elems[0] == 'FROM':
                    i = idx
            if i < 0:
                raise Exception('no FROM statement')
            lines.insert(i+1, line)
            return '\n'.join(lines)

        for env in ['http_proxy', 'https_proxy']:
            if env in os.environ:
                cls.dockerfile = insert_after_from(cls.dockerfile, 'ENV {0} {1}'.format(env, os.environ[env]))

        # f = io.FileIO(cls.dockerfile.encode('utf-8'))
        f = open('/Users/YUAN/Desktop/Dockerfile', 'w')
        f.write(cls.dockerfile.encode('utf-8'))
        f.close()

        if force or not img_exists(tag):
            if img_exists(tag):
                print "rm image {0} ...".format(tag)
                dckr.remove_image(tag)
            print 'build {0}...'.format(tag)
            for line in dckr.build(path="/Users/YUAN/Desktop", rm=True, tag=tag, decode=True, nocache=nocache):
                if 'stream' in line:
                    print line['stream'].strip()

            os.remove('/Users/YUAN/Desktop/Dockerfile')


class MIRAGESTTarget(MIRAGE_ST, Target):

    CONTAINER_NAME = 'bgperf_mirage_st_target'
    CONFIG_FILE_NAME = 'bgpd.json'

    def write_config(self, scenario_global_conf):
        config = {}
        config['local_asn'] = self.conf['as']
        config['local_id'] = self.conf['router-id']
        config['local_port'] = 179
        config['peers'] = []

        def gen_neighbor_config(n):
            peer = {}
            peer['remote_id'] = n['local-address']
            peer['remote_asn'] = n['as']
            peer['hold_time'] = 180
            peer['conn_retry_time'] = 240
            peer['remote_port'] = 179
            return peer

        with open('{0}/{1}'.format(self.host_dir, self.CONFIG_FILE_NAME), 'w') as f:
            for n in sorted(list(flatten(t.get('neighbors', {}).values() for t in scenario_global_conf['testers'])) + [scenario_global_conf['monitor']], key=lambda n: n['as']):
                peer = gen_neighbor_config(n)
                config['peers'].append(peer)
            f.write(json.dumps(config))
            f.flush()

    def get_startup_cmd(self):
        return '\n'.join(
            ['#!/bin/bash',
             'OCAML_SPACETIME_INTERVAL=100 Mirage-BGP/src/bgpd/bgpd --config {guest_dir}/{config_file_name} &',
             'disown -ah'
            ]
        ).format(
            guest_dir=self.guest_dir,
            config_file_name=self.CONFIG_FILE_NAME
        )
