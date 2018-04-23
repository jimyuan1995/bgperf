from base import *
import json


class Throughput(Container):
    CONTAINER_NAME = None
    GUEST_DIR = '/home/opam/config'

    def __init__(self, host_dir, conf, image='bgperf/throughput'):
        super(Throughput, self).__init__(self.CONTAINER_NAME, image, host_dir, self.GUEST_DIR, conf)

    def gen_host_config(self):
        host_config = dckr.create_host_config(
            binds=[
                '{0}:{1}'.format(os.path.abspath(self.host_dir), self.guest_dir)
            ],
            privileged=True,
            network_mode='bridge',
            cap_add=['NET_ADMIN']
        )
        return host_config

    @classmethod
    def build_image(cls, force=False, tag='bgperf/throughput', checkout='feature-integrate-test', nocache=False):
        cls.dockerfile = '''
    FROM mirage-bgp:latest

    RUN rm -rf mrt-format \
    && rm -rf Mirage-BGP

    COPY --chown=opam:opam mrt-format /home/opam/mrt-format
    COPY --chown=opam:opam Bgp-tests /home/opam/Mirage-BGP

    RUN cd Mirage-BGP/src/perf \
    && eval `opam config env` \
    && mirage configure -t unix --net socket \
    && make depend \
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
            lines.insert(i + 1, line)
            return '\n'.join(lines)

        for env in ['http_proxy', 'https_proxy']:
            if env in os.environ:
                cls.dockerfile = insert_after_from(cls.dockerfile, 'ENV {0} {1}'.format(env, os.environ[env]))

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

    def get_ipv4_addresses(self):
        return ["10.10.0.2"]


class ThroughputTarget(Throughput, Target):

    CONTAINER_NAME = 'bgperf_throughput_tester'
    CONFIG_FILE_NAME = 'config.json'

    def write_config(self, scenario_global_conf):
        config = {
          "relays": [
            {
              "remote_id": "10.10.0.3",
              "remote_port": 50001,
              "remote_asn": 1000,
              "local_id": "10.10.0.3",
              "local_port": 179,
              "local_asn": 1003
            },
            {
              "remote_id": "10.10.0.4",
              "remote_port": 50002,
              "remote_asn": 1000,
              "local_id": "10.10.0.4",
              "local_port": 179,
              "local_asn": 1004
            }
          ]
        }

        with open('{0}/{1}'.format(self.host_dir, self.CONFIG_FILE_NAME), 'w') as f:
            f.write(json.dumps(config))
            f.flush()

    def get_startup_cmd(self):
        return '\n'.join(
            ['#!/bin/bash',
             'sudo Mirage-BGP/src/perf/perf --config {guest_dir}/{config_file_name} -d -r 10 -m 500 -p 100'
             # 'disown -ah'
             ]
        ).format(
            guest_dir=self.guest_dir,
            config_file_name=self.CONFIG_FILE_NAME
        )

    def run(self, scenario_global_conf, dckr_net_name=''):
        ctn = super(Target, self).run(dckr_net_name)

        if not self.use_existing_config():
            self.write_config(scenario_global_conf)

        output = self.exec_startup_cmd(stream=True, detach=False)
        for lines in output: # This is the output
            for line in lines.strip().split('\n'):
                print line

        return ctn