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
    def build_image(cls, force=False, tag='bgperf/mirage', checkout='bgperf', nocache=False):
        cls.dockerfile = '''
FROM mirage-bgp:latest

RUN rm -rf mrt-format \
&& rm -rf Mirage-BGP

COPY --chown=opam:opam mrt-format /home/opam/mrt-format
COPY --chown=opam:opam Bgp4 /home/opam/Mirage-BGP
COPY --chown=opam:opam ocaml-lazy-trie /home/opam/ocaml-lazy-trie

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


class MIRAGETarget(MIRAGE, Target):

    CONTAINER_NAME = 'bgperf_mirage_target'
    CONFIG_FILE_NAME = 'bgpd.json'

    def write_config(self, scenario_global_conf, args):
        MIRAGETarget.args_global = args

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
            if args.peer_group:
                peer['peer_group'] = 1


            if 'filter' in n:
                for p in (n['filter']['in'] if 'in' in n['filter'] else []):
                    peer['inbound_filter'] = 'route_map 0'
            return peer

        count = 0
        with open('{0}/{1}'.format(self.host_dir, self.CONFIG_FILE_NAME), 'w') as f:
            if 'policy' in scenario_global_conf:
                seq = 10
                for k, v in scenario_global_conf['policy'].iteritems():
                    match_info = []
                    for i, match in enumerate(v['match']):
                        n = '{0}_match_{1}'.format(k, i)
                        if match['type'] == 'prefix':
                            prefix_list = []
                            for p in match['value']:
                                prefix_list.append(p)
                            config['prefix_list 1'.format(count)] = prefix_list
                        elif match['type'] == 'as-path':
                            f.write(''.join('ip as-path access-list {0} deny _{1}_\n'.format(n, p) for p in match['value']))
                            f.write('ip as-path access-list {0} permit .*\n'.format(n))
                        elif match['type'] == 'community':
                            f.write(''.join('ip community-list standard {0} permit {1}\n'.format(n, p) for p in match['value']))
                            f.write('ip community-list standard {0} permit\n'.format(n))
                        elif match['type'] == 'ext-community':
                            f.write(''.join('ip extcommunity-list standard {0} permit {1} {2}\n'.format(n, *p.split(':', 1)) for p in match['value']))
                            f.write('ip extcommunity-list standard {0} permit\n'.format(n))

                        match_info.append((match['type'], n))

                    route_map = []

                    entry = {}
                    entry['order'] = 10
                    entry['permit'] = False
                    entry['conditions'] = ['prefix_list 1']
                    entry['actions'] = []
                    route_map.append(entry)

                    entry = {}
                    entry['order'] = 20
                    entry['permit'] = True
                    entry['conditions'] = []
                    entry['actions'] = []
                    route_map.append(entry)

                    config['route_map 0'] = route_map

                    # f.write('route-map {0} permit {1}\n'.format(k, seq))
                    # for info in match_info:
                    #     if info[0] == 'prefix':
                    #         f.write('match ip address prefix-list {0}\n'.format(info[1]))
                    #     elif info[0] == 'as-path':
                    #         f.write('match as-path {0}\n'.format(info[1]))
                    #     elif info[0] == 'community':
                    #         f.write('match community {0}\n'.format(info[1]))
                    #     elif info[0] == 'ext-community':
                    #         f.write('match extcommunity {0}\n'.format(info[1]))
                    #
                    # seq += 10


            count = 0
            for n in sorted(list(flatten(t.get('neighbors', {}).values() for t in scenario_global_conf['testers'])) + [scenario_global_conf['monitor']], key=lambda n: n['as']):
                peer = gen_neighbor_config(n)
                name = 'neighbor {0}'.format(count)
                config[name] = peer
                count += 1
            f.write(json.dumps(config))
            f.flush()

    def get_startup_cmd(self):
        if MIRAGETarget.args_global.peer_group:
            return '\n'.join(
                ['#!/bin/bash',
                 'cd {guest_dir}/',
                 'sudo ../Mirage-BGP/src/bgpd/bgpd --config {config_file_name} --test --runtime 90 --pg_transit &',
                 'disown -ah'
                ]
            ).format(
                guest_dir=self.guest_dir,
                config_file_name=self.CONFIG_FILE_NAME
            )
        else:
            return '\n'.join(
                ['#!/bin/bash',
                 'cd {guest_dir}/',
                 'sudo ../Mirage-BGP/src/bgpd/bgpd --config {config_file_name} --test --runtime 90 &',
                 'disown -ah'
                 ]
            ).format(
                guest_dir=self.guest_dir,
                config_file_name=self.CONFIG_FILE_NAME
            )


