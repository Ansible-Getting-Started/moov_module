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


author(s):
    - Bianca Henderson (@beeankha)
    - John Lieske (@JohnLieske)
    - Jake Jackson(@thedoubl3j)
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
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

from ansible.module_utils.basic import AnsibleModule

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
        new=dict(type='bool', required=False, default=False)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        return result

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['original_message'] = module.params['name']
    result['message'] = 'goodbye'

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if module.params['new']:
        result['changed'] = True

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if module.params['name'] == 'fail me':
        module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
