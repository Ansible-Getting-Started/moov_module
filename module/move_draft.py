#!/usr/bin/python

# Copyright: (c) 2018, [OUR NAMES] <[OUR NAMES]@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: move

short_description: Moves files

version_added: "2.8"

description:
    - The C(move) module moves, or renames, files and directories on the local or on a remote machine's filesystem.
      Use the M(fetch) module to copy files from remote locations to the local box.
      If you need variable interpolation in copied files, use the M(template) module instead.
options:
    name:
        description:
            - This is the message to send to the sample module
        required: true
    new:
        description:
            - Control to demo if the result of this module is changed or not
        required: false

notes:
- For Windows targets, use the M(win_file) module instead.
seealso:
- module: assemble
- module: copy
- module: file
- module: stat
- module: template
- module: win_file

author(s):
    - Bianca Henderson (@beeankha)
    - John Lieske (@JohnLieske)
    - Jake Jackson (@thedoubl3j)
'''

EXAMPLES = '''
# Move a file from source to a new destination
- name: Move with permissions
  move:
    src: /etc/app/fake.conf
    dest: /etc/app1/fake.conf
    owner: cow
    group: cowsay
    mode: 0644

# Move a file, same examples as above with symbolic mode equal to 0644
- name: Move with symbolic permissions
  move:
    src: /etc/app/fake.conf
    dest: /etc/app1/fake.conf
    owner: cow
    group: cowsay
    mode: u=rw,g=r,o=r

# Move a file while adding and removing some persissions in symbolic mode
- name: Move file and change permissions
  move:
    src: /etc/app/fake.conf
    dest: /etc/app1/fake.conf
    owner: cow
    group: cowsay
    mode: u+rw,g-wx,o-rwx

# Move a file and create a back up at the source location
- name: move a file and create a back up
  move:
    src: /mine/httpd.conf
    dest: /etc/httpd.conf
    owner: root
    group: root
    mode: 0644
    backup: yes

#Renaming a file
# Move a file from source to a new destination
- name: Renaming a file
  move:
    src: /etc/app/fake.conf
    dest: /etc/app/fake1.conf
    owner: cow
    group: cowsay
    mode: 0644

#Move multiple files into one directory
- name: Move files into one directory_mode
  move:
    src: files={{items}}
    with_items
      - path/to/file1
      - path/to/file2
    dest: /path/to/new/dir

'''

RETURN = '''
dest:
    description: destination file/path
    returned: success
    type: string
    sample: /path/to/file.txt
src:
    description: source file used for the copy on the target machine
    returned: changed
    type: string
    sample: /home/httpd/.ansible/tmp/ansible-tmp-1423796390.97-147729857856000/source
md5sum:
    description: md5 checksum of the file after running copy
    returned: when supported
    type: string
    sample: 2a5aeecc61dc98c4d780b14b330e3282
checksum:
    description: sha1 checksum of the file after running copy
    returned: success
    type: string
    sample: 6e642bb8dd5c2e027bf21dd923337cbb4214f827
backup_file:
    description: name of backup file created
    returned: changed and if backup=yes
    type: string
    sample: /path/to/file.txt.2015-02-12@22:09~
gid:
    description: group id of the file, after execution
    returned: success
    type: int
    sample: 100
group:
    description: group of the file, after execution
    returned: success
    type: string
    sample: httpd
owner:
    description: owner of the file, after execution
    returned: success
    type: string
    sample: httpd
uid:
    description: owner id of the file, after execution
    returned: success
    type: int
    sample: 100
mode:
    description: permissions of the target, after execution
    returned: success
    type: string
    sample: 0644
size:
    description: size of the target, after execution
    returned: success
    type: int
    sample: 1220
state:
    description: state of the target, after execution
    returned: success
    type: string
    sample: file
'''

import os
import os.path
import shutil
import filecmp
import pwd
import grp
import stat
import errno
import tempfile
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native

class AnsibleModuleError(Exception):
    def __init__(self, results):
        self.results = results

    def __repr__(self):
        print('AnsibleModuleError(results={0})'.format(self.results))


def split_pre_existing_dir(dirname):
    '''
    Return the first pre-existing directory and a list of the new directories that will be created.
    '''
    head, tail = os.path.split(dirname)
    b_head = to_bytes(head, errors='surrogate_or_strict')
    if head == '':
        return ('.', [tail])
    if not os.path.exists(b_head):
        if head == '/':
            raise AnsibleModuleError(results={'msg': "The '/' directory doesn't exist on this machine."})
        (pre_existing_dir, new_directory_list) = split_pre_existing_dir(head)
    else:
        return (head, [tail])
    new_directory_list.append(tail)
    return (pre_existing_dir, new_directory_list)


def adjust_recursive_directory_permissions(pre_existing_dir, new_directory_list, module, directory_args, changed):
    '''
    Walk the new directories list and make sure that permissions are as we would expect
    '''

    if new_directory_list:
        working_dir = os.path.join(pre_existing_dir, new_directory_list.pop(0))
        directory_args['path'] = working_dir
        changed = module.set_fs_attributes_if_different(directory_args, changed)
        changed = adjust_recursive_directory_permissions(working_dir, new_directory_list, module, directory_args, changed)
    return changed


def chown_recursive(path, module):
    changed = False
    owner = module.params['owner']
    group = module.params['group']

    if owner is not None:
        if not module.check_mode:
            for dirpath, dirnames, filenames in os.walk(path):
                owner_changed = module.set_owner_if_different(dirpath, owner, False)
                if owner_changed is True:
                    changed = owner_changed
                for dir in [os.path.join(dirpath, d) for d in dirnames]:
                    owner_changed = module.set_owner_if_different(dir, owner, False)
                    if owner_changed is True:
                        changed = owner_changed
                for file in [os.path.join(dirpath, f) for f in filenames]:
                    owner_changed = module.set_owner_if_different(file, owner, False)
                    if owner_changed is True:
                        changed = owner_changed
        else:
            uid = pwd.getpwnam(owner).pw_uid
            for dirpath, dirnames, filenames in os.walk(path):
                owner_changed = (os.stat(dirpath).st_uid != uid)
                if owner_changed is True:
                    changed = owner_changed
                for dir in [os.path.join(dirpath, d) for d in dirnames]:
                    owner_changed = (os.stat(dir).st_uid != uid)
                    if owner_changed is True:
                        changed = owner_changed
                for file in [os.path.join(dirpath, f) for f in filenames]:
                    owner_changed = (os.stat(file).st_uid != uid)
                    if owner_changed is True:
                        changed = owner_changed
    if group is not None:
        if not module.check_mode:
            for dirpath, dirnames, filenames in os.walk(path):
                group_changed = module.set_group_if_different(dirpath, group, False)
                if group_changed is True:
                    changed = group_changed
                for dir in [os.path.join(dirpath, d) for d in dirnames]:
                    group_changed = module.set_group_if_different(dir, group, False)
                    if group_changed is True:
                        changed = group_changed
                for file in [os.path.join(dirpath, f) for f in filenames]:
                    group_changed = module.set_group_if_different(file, group, False)
                    if group_changed is True:
                        changed = group_changed
        else:
            gid = grp.getgrnam(group).gr_gid
            for dirpath, dirnames, filenames in os.walk(path):
                group_changed = (os.stat(dirpath).st_gid != gid)
                if group_changed is True:
                    changed = group_changed
                for dir in [os.path.join(dirpath, d) for d in dirnames]:
                    group_changed = (os.stat(dir).st_gid != gid)
                    if group_changed is True:
                        changed = group_changed
                for file in [os.path.join(dirpath, f) for f in filenames]:
                    group_changed = (os.stat(file).st_gid != gid)
                    if group_changed is True:
                        changed = group_changed

    return changed


def move_diff_files(src, dest, module):
    changed = False
    owner = module.params['owner']
    group = module.params['group']
    local_follow = module.params['local_follow']
    diff_files = filecmp.dircmp(src, dest).diff_files
    if len(diff_files):
        changed = True
    if not module.check_mode:
        for item in diff_files:
            src_item_path = os.path.join(src, item)
            dest_item_path = os.path.join(dest, item)
            b_src_item_path = to_bytes(src_item_path, errors='surrogate_or_strict')
            b_dest_item_path = to_bytes(dest_item_path, errors='surrogate_or_strict')
            if os.path.islink(b_src_item_path) and local_follow is False:
                linkto = os.readlink(b_src_item_path)
                os.symlink(linkto, b_dest_item_path)
            else:
                shutil.copyfile(b_src_item_path, b_dest_item_path)

            if owner is not None:
                module.set_owner_if_different(b_dest_item_path, owner, False)
            if group is not None:
                module.set_group_if_different(b_dest_item_path, group, False)
            changed = True
    return changed


def move_left_only(src, dest, module):
    changed = False
    owner = module.params['owner']
    group = module.params['group']
    local_follow = module.params['local_follow']
    left_only = filecmp.dircmp(src, dest).left_only
    if len(left_only):
        changed = True
    if not module.check_mode:
        for item in left_only:
            src_item_path = os.path.join(src, item)
            dest_item_path = os.path.join(dest, item)
            b_src_item_path = to_bytes(src_item_path, errors='surrogate_or_strict')
            b_dest_item_path = to_bytes(dest_item_path, errors='surrogate_or_strict')

            if os.path.islink(b_src_item_path) and os.path.isdir(b_src_item_path) and local_follow is True:
                shutil.copytree(b_src_item_path, b_dest_item_path, symlinks=not(local_follow))
                chown_recursive(b_dest_item_path, module)

            if os.path.islink(b_src_item_path) and os.path.isdir(b_src_item_path) and local_follow is False:
                linkto = os.readlink(b_src_item_path)
                os.symlink(linkto, b_dest_item_path)

            if os.path.islink(b_src_item_path) and os.path.isfile(b_src_item_path) and local_follow is True:
                shutil.copyfile(b_src_item_path, b_dest_item_path)
                if owner is not None:
                    module.set_owner_if_different(b_dest_item_path, owner, False)
                if group is not None:
                    module.set_group_if_different(b_dest_item_path, group, False)

            if os.path.islink(b_src_item_path) and os.path.isfile(b_src_item_path) and local_follow is False:
                linkto = os.readlink(b_src_item_path)
                os.symlink(linkto, b_dest_item_path)

            if not os.path.islink(b_src_item_path) and os.path.isfile(b_src_item_path):
                shutil.copyfile(b_src_item_path, b_dest_item_path)
                if owner is not None:
                    module.set_owner_if_different(b_dest_item_path, owner, False)
                if group is not None:
                    module.set_group_if_different(b_dest_item_path, group, False)

            if not os.path.islink(b_src_item_path) and os.path.isdir(b_src_item_path):
                shutil.copytree(b_src_item_path, b_dest_item_path, symlinks=not(local_follow))
                chown_recursive(b_dest_item_path, module)

            changed = True
    return changed


def move_common_dirs(src, dest, module):
    changed = False
    common_dirs = filecmp.dircmp(src, dest).common_dirs
    for item in common_dirs:
        src_item_path = os.path.join(src, item)
        dest_item_path = os.path.join(dest, item)
        b_src_item_path = to_bytes(src_item_path, errors='surrogate_or_strict')
        b_dest_item_path = to_bytes(dest_item_path, errors='surrogate_or_strict')
        diff_files_changed = move_diff_files(b_src_item_path, b_dest_item_path, module)
        left_only_changed = move_left_only(b_src_item_path, b_dest_item_path, module)
        if diff_files_changed or left_only_changed:
            changed = True
    return changed

# Below is possible code for DELETING the directory
# or file that was moved using this module.

def ensure_absent(path):
    b_path = to_bytes(path, errors='surrogate_or_strict')
    prev_state = get_state(b_path)
    result = {}

    if prev_state != 'absent':
# I got the code below from the file.py module, and don't think we really need
# it, since 'state = absent' (to delete the original location of the file or
# directory) should NOT be optional
#        if not module.check_mode:
#            if prev_state == 'directory':
#                try:
#                    shutil.rmtree(b_path, ignore_errors=False)
#                except Exception as e:
#                    raise AnsibleModuleError(results={'msg': "rmtree failed: %s" % to_native(e)})
#            else:
#                try:
#                    os.unlink(b_path)
#                except OSError as e:
#                    if e.errno != errno.ENOENT:  # It may already have been removed
#                        raise AnsibleModuleError(results={'msg': "unlinking failed: %s " % to_native(e),
#                                                          'path': path})
        diff = initial_diff(path, 'absent', prev_state)
        result.update({'path': path, 'changed': True, 'diff': diff})
    else:
        result.update({'path': path, 'changed': False})

    return result


def main():

    module = AnsibleModule(
        # not checking because of daisy chain to file module
        argument_spec=dict(
            src=dict(type='path'),
            _original_basename=dict(type='str'),  # used to handle 'dest is a directory' via template, a slight hack
            content=dict(type='str', no_log=True),
            dest=dict(type='path', required=True),
            backup=dict(type='bool', default=False),
            force=dict(type='bool', default=True, aliases=['thirsty']),
            validate=dict(type='str'),
            directory_mode=dict(type='raw'),
            remote_src=dict(type='bool'),
            local_follow=dict(type='bool'),
            checksum=dict(),
        ),
        add_file_common_args=True,
        supports_check_mode=True,
    )

    src = module.params['src']
    b_src = to_bytes(src, errors='surrogate_or_strict')
    dest = module.params['dest']
    # Make sure we always have a directory component for later processing
    if os.path.sep not in dest:
        dest = '.{0}{1}'.format(os.path.sep, dest)
    b_dest = to_bytes(dest, errors='surrogate_or_strict')
    backup = module.params['backup']
    force = module.params['force']
    _original_basename = module.params.get('_original_basename', None)
    validate = module.params.get('validate', None)
    follow = module.params['follow']
    local_follow = module.params['local_follow']
    mode = module.params['mode']
    owner = module.params['owner']
    group = module.params['group']
    remote_src = module.params['remote_src']
    checksum = module.params['checksum']
    # adding two more here for DELETE function (hopefully this is right?)
    state = module.params['state']
    path = module.params['path']

    if not os.path.exists(b_src):
        module.fail_json(msg="Source %s not found" % (src))
    if not os.access(b_src, os.R_OK):
        module.fail_json(msg="Source %s not readable" % (src))

    # Preserve is usually handled in the action plugin but mode + remote_src has to be done on the
    # remote host
    if module.params['mode'] == 'preserve':
        module.params['mode'] = '0%03o' % stat.S_IMODE(os.stat(b_src).st_mode)
    mode = module.params['mode']

    checksum_dest = None

    if os.path.isfile(src):
        checksum_src = module.sha1(src)
    else:
        checksum_src = None

    # Backwards compat only.  This will be None in FIPS mode
    try:
        if os.path.isfile(src):
            md5sum_src = module.md5(src)
        else:
            md5sum_src = None
    except ValueError:
        md5sum_src = None

    changed = False

    if checksum and checksum_src != checksum:
        module.fail_json(
            msg='Copied file does not match the expected checksum. Transfer failed.',
            checksum=checksum_src,
            expected_checksum=checksum
        )

    # Special handling for recursive copy - create intermediate dirs
    if _original_basename and dest.endswith(os.sep):
        dest = os.path.join(dest, _original_basename)
        b_dest = to_bytes(dest, errors='surrogate_or_strict')
        dirname = os.path.dirname(dest)
        b_dirname = to_bytes(dirname, errors='surrogate_or_strict')
        if not os.path.exists(b_dirname):
            try:
                (pre_existing_dir, new_directory_list) = split_pre_existing_dir(dirname)
            except AnsibleModuleError as e:
                e.result['msg'] += ' Could not move to {0}'.format(dest)
                module.fail_json(**e.results)

            os.makedirs(b_dirname)
            directory_args = module.load_file_common_arguments(module.params)
            directory_mode = module.params["directory_mode"]
            if directory_mode is not None:
                directory_args['mode'] = directory_mode
            else:
                directory_args['mode'] = None
            adjust_recursive_directory_permissions(pre_existing_dir, new_directory_list, module, directory_args, changed)

    if os.path.isdir(b_dest):
        basename = os.path.basename(src)
        if _original_basename:
            basename = _original_basename
        dest = os.path.join(dest, basename)
        b_dest = to_bytes(dest, errors='surrogate_or_strict')

    if os.path.exists(b_dest):
        if os.path.islink(b_dest) and follow:
            b_dest = os.path.realpath(b_dest)
            dest = to_native(b_dest, errors='surrogate_or_strict')
        if not force:
            module.exit_json(msg="file already exists", src=src, dest=dest, changed=False)
        if os.access(b_dest, os.R_OK) and os.path.isfile(dest):
            checksum_dest = module.sha1(dest)
    else:
        if not os.path.exists(os.path.dirname(b_dest)):
            try:
                # os.path.exists() can return false in some
                # circumstances where the directory does not have
                # the execute bit for the current user set, in
                # which case the stat() call will raise an OSError
                os.stat(os.path.dirname(b_dest))
            except OSError as e:
                if "permission denied" in to_native(e).lower():
                    module.fail_json(msg="Destination directory %s is not accessible" % (os.path.dirname(dest)))
            module.fail_json(msg="Destination directory %s does not exist" % (os.path.dirname(dest)))

    if not os.access(os.path.dirname(b_dest), os.W_OK) and not module.params['unsafe_writes']:
        module.fail_json(msg="Destination %s not writable" % (os.path.dirname(dest)))

    backup_file = None
    if checksum_src != checksum_dest or os.path.islink(b_dest):
        if not module.check_mode:
            try:
                if backup:
                    if os.path.exists(b_dest):
                        backup_file = module.backup_local(dest)
                # allow for conversion from symlink.
                if os.path.islink(b_dest):
                    os.unlink(b_dest)
                    open(b_dest, 'w').close()
                if validate:
                    # if we have a mode, make sure we set it on the temporary
                    # file source as some validations may require it
                    if mode is not None:
                        module.set_mode_if_different(src, mode, False)
                    if owner is not None:
                        module.set_owner_if_different(src, owner, False)
                    if group is not None:
                        module.set_group_if_different(src, group, False)
                    if "%s" not in validate:
                        module.fail_json(msg="validate must contain %%s: %s" % (validate))
                    (rc, out, err) = module.run_command(validate % src)
                    if rc != 0:
                        module.fail_json(msg="failed to validate", exit_status=rc, stdout=out, stderr=err)
                b_mysrc = b_src
                if remote_src and os.path.isfile(b_src):
                    _, b_mysrc = tempfile.mkstemp(dir=os.path.dirname(b_dest))

                    shutil.copyfile(b_src, b_mysrc)
                    try:
                        shutil.copystat(b_src, b_mysrc)
                    except OSError as err:
                        if err.errno == errno.ENOSYS and mode == "preserve":
                            module.warn("Unable to copy stats {0}".format(to_native(b_src)))
                        else:
                            raise
                module.atomic_move(b_mysrc, dest, unsafe_writes=module.params['unsafe_writes'])
            except (IOError, OSError):
                module.fail_json(msg="failed to move: %s to %s" % (src, dest), traceback=traceback.format_exc())
        changed = True
    else:
        changed = False

    if checksum_src is None and checksum_dest is None:
        if remote_src and os.path.isdir(module.params['src']):
            b_src = to_bytes(module.params['src'], errors='surrogate_or_strict')
            b_dest = to_bytes(module.params['dest'], errors='surrogate_or_strict')

            if src.endswith(os.path.sep) and os.path.isdir(module.params['dest']):
                diff_files_changed = move_diff_files(b_src, b_dest, module)
                left_only_changed = move_left_only(b_src, b_dest, module)
                common_dirs_changed = move_common_dirs(b_src, b_dest, module)
                owner_group_changed = chown_recursive(b_dest, module)
                delete_origin = ensure_absent(path) # just copying the above, creating 'delete_origin'
                if diff_files_changed or left_only_changed or common_dirs_changed or owner_group_changed:
                    changed = True

            if src.endswith(os.path.sep) and not os.path.exists(module.params['dest']):
                b_basename = to_bytes(os.path.basename(src), errors='surrogate_or_strict')
                b_dest = to_bytes(os.path.join(b_dest, b_basename), errors='surrogate_or_strict')
                b_src = to_bytes(os.path.join(module.params['src'], ""), errors='surrogate_or_strict')
                if not module.check_mode:
                    shutil.copytree(b_src, b_dest, symlinks=not(local_follow))
                chown_recursive(dest, module)
                changed = True

            if not src.endswith(os.path.sep) and os.path.isdir(module.params['dest']):
                b_basename = to_bytes(os.path.basename(src), errors='surrogate_or_strict')
                b_dest = to_bytes(os.path.join(b_dest, b_basename), errors='surrogate_or_strict')
                b_src = to_bytes(os.path.join(module.params['src'], ""), errors='surrogate_or_strict')
                if not module.check_mode and not os.path.exists(b_dest):
                    shutil.copytree(b_src, b_dest, symlinks=not(local_follow))
                    changed = True
                    chown_recursive(dest, module)
                if module.check_mode and not os.path.exists(b_dest):
                    changed = True
                if os.path.exists(b_dest):
                    diff_files_changed = move_diff_files(b_src, b_dest, module)
                    left_only_changed = move_left_only(b_src, b_dest, module)
                    common_dirs_changed = move_common_dirs(b_src, b_dest, module)
                    owner_group_changed = chown_recursive(b_dest, module)
                    delete_origin = ensure_absent(path) # just copying the above, creating 'delete_origin'
                    if diff_files_changed or left_only_changed or common_dirs_changed or owner_group_changed:
                        changed = True

            if not src.endswith(os.path.sep) and not os.path.exists(module.params['dest']):
                b_basename = to_bytes(os.path.basename(module.params['src']), errors='surrogate_or_strict')
                b_dest = to_bytes(os.path.join(b_dest, b_basename), errors='surrogate_or_strict')
                if not module.check_mode and not os.path.exists(b_dest):
                    os.makedirs(b_dest)
                    b_src = to_bytes(os.path.join(module.params['src'], ""), errors='surrogate_or_strict')
                    diff_files_changed = move_diff_files(b_src, b_dest, module)
                    left_only_changed = move_left_only(b_src, b_dest, module)
                    common_dirs_changed = move_common_dirs(b_src, b_dest, module)
                    owner_group_changed = chown_recursive(b_dest, module)
                    delete_origin = ensure_absent(path) # just copying the above, creating 'delete_origin'
                    if diff_files_changed or left_only_changed or common_dirs_changed or owner_group_changed:
                        changed = True
                if module.check_mode and not os.path.exists(b_dest):
                    changed = True

    res_args = dict(
        dest=dest, src=src, md5sum=md5sum_src, checksum=checksum_src, changed=changed
    )
    if backup_file:
        res_args['backup_file'] = backup_file

    module.params['dest'] = dest
    if not module.check_mode:
        file_args = module.load_file_common_arguments(module.params)
        res_args['changed'] = module.set_fs_attributes_if_different(file_args, res_args['changed'])

    module.exit_json(**res_args)


if __name__ == '__main__':
    main()
