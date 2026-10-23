"""Private rc worker for completed VM instances, not an operator entrypoint.

No enrollment, install/resume, package bootstrap, discovery or recovery is done.
The RC caller pins its retained frozen public payload, not the operator's download
path. A standalone identity check precedes package imports; source drift refuses
startup, and the worker rechecks the saved identity before runtime commands.
Use install.sh for all operator workflows. Publication requires completed
integration/restart/readiness phases; native acceptance is a separate test gate.
"""

import re
import os
import stat
import sys

from .deploy import Deployment, COMPLETE_MESSAGE
from .host import Runner, require_host
from .office_vm import start_native_vm, stop_native_vm
from .state import Registry, config_digest, private_json
from .host import read_private


def run(action, instance, *, registry, runner):
    if action not in ('start','stop') or not isinstance(instance,str) or not re.fullmatch(r'[a-z][a-z0-9]{0,7}',instance):
        raise ValueError('Invalid private VM boot action/identity')
    require_host(runner)
    for path in (registry.root,registry.instance_path(instance)):
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077
                or path.resolve(strict=True)!=path):
            raise ValueError('Private existing VM instance state is required')
    with registry.locked(create=False):
        config=registry.load(instance)
        if config.backend not in ('eurooffice','collabora'):
            raise ValueError('This instance has no managed office VM')
        # No secrets are loaded by boot/shutdown; Docker retains its private
        # configuration. The existing Deployment verifies the saved version lock.
        deployment=Deployment(config,{},runner,registry=registry)
        deployment.require_original_artifact()
        status=registry.status(instance)
        if action=='stop':
            if status['state'] not in ('ready','removing','installing','failed'):
                raise ValueError('Unallocated/removed instance is not a boot-service shutdown target')
            return stop_native_vm(deployment)
        digest=config_digest(config)
        if (status['state']!='ready' or read_private(deployment.state/'complete')!=COMPLETE_MESSAGE
                or read_private(deployment.state/'allow-vm-start')!=digest+'\n'):
            raise ValueError('VM boot requires a completed ready instance and bound permission')
        journal=private_json(deployment.state/'deployment.json')
        if (not isinstance(journal,dict) or type(journal.get('schema_version')) is not int
                or journal['schema_version']!=config.schema_version or journal.get('config_sha256')!=digest
                or not isinstance(journal.get('steps'),dict) or not journal['steps']
                or any(not isinstance(step,dict) or step.get('state')!='complete' for step in journal['steps'].values())):
            raise ValueError('VM boot refuses an incomplete or changed installation journal')
        deployment.require_running_jail(config.nextcloud_jail)
        return start_native_vm(deployment)


def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if len(argv)!=2:
        print('Private VM rc worker requires an action and instance; use install.sh for operator workflows.',file=sys.stderr)
        return 1
    try:
        run(argv[0],argv[1],registry=Registry(),runner=Runner())
    except (OSError,ValueError,RuntimeError,TypeError,KeyError):
        # Do not echo dependency/exception strings into boot console logs.
        print('Office VM boot/shutdown refused; retain private instance state and inspect with install.sh.',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
