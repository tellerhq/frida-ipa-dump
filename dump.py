#!/usr/bin/env python3
# encoding: utf-8

from __future__ import print_function

import codecs
import sys
import tempfile
import os
import shutil
from collections import namedtuple

import frida


def fatal(reason):
    print(reason)
    sys.exit(-1)


def find_app(app_name_or_id, device_id, device_ip):
    if device_id is None:
        if device_ip is None:
            dev = frida.get_usb_device()
        else:
            frida.get_device_manager().add_remote_device(device_ip)
            dev = frida.get_device("tcp@" + device_ip)
    else:
        try:
            dev = next(dev for dev in frida.enumerate_devices()
                       if dev.id.startswith(device_id))
        except StopIteration:
            fatal('device id %s not found' % device_id)

    if dev.type not in ('tether', 'remote', 'usb'):
        fatal('unable to find device')

    print(list(dev.enumerate_processes()))
    try:
        app = next(app for app in dev.enumerate_applications() if
                   app_name_or_id == app.identifier or
                   app_name_or_id == app.name)
    except:
        print('app "%s" not found' % app_name_or_id)
        print('installed app:')
        for app in dev.enumerate_applications():
            print('%s (%s)' % (app.name, app.identifier))
        fatal('')

    return dev, app


class Task(object):

    def __init__(self, session, path, size):
        self.session = session
        self.path = path
        self.size = size
        self.file = open(self.path, 'wb')

    def write(self, data):
        self.file.write(data)

    def finish(self):
        self.close()

    def close(self):
        self.file.close()


class IPADump(object):

    def __init__(self, device, pid, output=None, verbose=False, keep_watch=False):
        self.device = device
        self.pid = pid
        self.session = None
        self.cwd = None
        self.tasks = {}
        self.output = output
        self.verbose = verbose
        self.opt = {
            'keepWatch': keep_watch,
        }
        self.ipa_name = ''

    def on_download_start(self, session, size, **kwargs):
        self.tasks[session] = Task(session, self.ipa_name, size)

    def on_download_data(self, session, data, **kwargs):
        self.tasks[session].write(data)

    def on_download_finish(self, session, **kwargs):
        self.close_session(session)

    def on_download_error(self, session, **kwargs):
        self.close_session(session)

    def close_session(self, session):
        self.tasks[session].finish()
        del self.tasks[session]

    def on_message(self, msg, data):
        print(".")
        if msg.get('type') != 'send':
            print('unknown message:', msg)
            return

        payload = msg.get('payload', {})
        subject = payload.get('subject')
        if subject == 'download':
            method_mapping = {
                'start': self.on_download_start,
                'data': self.on_download_data,
                'end': self.on_download_finish,
                'error': self.on_download_error,
            }
            method = method_mapping[payload.get('event')]
            method(data=data, **payload)
        elif subject == 'finish':
            print('bye')
            self.session.detach()
            sys.exit(0)
        else:
            print('unknown message')
            print(msg)

    def dump(self):
        def on_console(level, text):
            if not self.verbose and level == 'info':
                return
            print('[%s]' % level, text)

        on_console('info', 'attaching to target')
        pid = self.pid
        print("attaching...")
        session = self.device.attach(pid)
        print("attached")
        script = session.create_script(self.agent_source)
        script.set_log_handler(on_console)
        script.on('message', self.on_message)
        script.load()

        self.plugins = script.exports.plugins()
        self.script = script
        root = self.script.exports.root()
        container = self.script.exports.data()+"/tmp"
        decrypted = self.script.exports.decrypt(root, container)
        self.script.exports.archive(root, container, decrypted, self.opt)

        print("detach")
        session.detach()

    def load_agent(self):
        agent = os.path.join('agent', 'dist.js')
        with codecs.open(agent, 'r', 'utf-8') as fp:
            self.agent_source = fp.read()

    def run(self):
        self.load_agent()
        if self.output is None:
            print(str(self.pid))
            ipa_name = '.'.join([str(self.pid), 'ipa'])
        elif os.path.isdir(self.output):
            ipa_name = os.path.join(self.output, '%s.%s' %
                                    (self.pid, 'ipa'))
        else:
            ipa_name = self.output

        self.ipa_name = ipa_name
        self.dump()
        print('Output: %s' % ipa_name)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', nargs='?', help='device id (prefix)')
    parser.add_argument('--ip', nargs='?', help='ip to connect over network')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument("-p", "--pid", help="pid")
    parser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
    parser.add_argument('--keep-watch', action='store_true',
                        default=False, help='preserve WatchOS app')
    args = parser.parse_args()

    dev = frida.get_usb_device()

    task = IPADump(dev, int(args.pid),
                   keep_watch=args.keep_watch,
                   output=args.output,
                   verbose=args.verbose)
    task.run()


if __name__ == '__main__':
    main()
