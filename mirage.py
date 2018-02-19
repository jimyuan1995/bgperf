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


class MIRAGE(Container):
    CONTAINER_NAME = None
    GUEST_DIR = '/home/opam/config'

    def __init__(self, host_dir, conf, image='bgperf/mirage'):
        super(MIRAGE, self).__init__(self.CONTAINER_NAME, image, host_dir, self.GUEST_DIR, conf)

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
    def build_image(cls, force=False, tag='bgperf/mirage', checkout='feature-index-storage', nocache=False):
        cls.dockerfile = '''
FROM mirage-bgp:latest

RUN cd Mirage-BGP/src/bgpd \
&& git checkout {0} \
&& git pull \
&& eval `opam config env`\
&& mirage clean \
&& mirage configure -t unix --net socket \
&& make depend \
&& make
'''.format(checkout)
        super(MIRAGE, cls).build_image(force, tag, nocache)


class MIRAGETarget(MIRAGE, Target):

    CONTAINER_NAME = 'bgperf-mirage-bgp'
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
             '/home/opam/host/script/sync_bgperf.sh'
            ]
        ).format(
            guest_dir=self.guest_dir,
            config_file_name=self.CONFIG_FILE_NAME)
