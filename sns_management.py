#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = """
module: sns_management
short_description: Manages AWS SNS topics, subscriptions, and platforms
description:
    - The M(sns_management) module allows you to create, delete, and manage subscriptions for AWS SNS topics, as well
      as create and manage SNS platform applications and endpoints.
version_added: 2.0
author:
  - "Joel Thompson (@joelthompson)"
  - "Fernando Jose Pando (@nand0p)"
  - "Michael Pappas (@mpappas86)"
options:
  name:
    description:
      - The name or ARN of the SNS topic/platform app/platform endpoint to converge
    required: True
  state:
    description:
      - Whether to create or destroy the SNS topic/platform app/platform endpoint
    required: False
    default: present
    choices: ["absent", "present"]
  sns_type:
    description:
      - Whether this is an SNS topic, platform app, or platform endpoint
    required: True
    default: "topic"
    choices: ["topic", "platform_app", "platform_endpoint"]
  display_name:
    description:
      - Display name of the topic (topic only)
    required: False
    default: None
  policy:
    description:
      - Policy to apply to the SNS topic (topic only)
    required: False
    default: None
  delivery_policy:
    description:
      - Delivery policy to apply to the SNS topic (topic only)
    required: False
    default: None
  subscriptions:
    description:
      - List of subscriptions to apply to the topic. Note that AWS requires
        subscriptions to be confirmed, so you will need to confirm any new
        subscriptions. (topic only)
    required: False
    default: []
  purge_subscriptions:
    description:
      - "Whether to purge any subscriptions not listed here. (topic only)
        NOTE: AWS does not allow you to purge any PendingConfirmation
        subscriptions, so if any exist and would be purged, they are silently
        skipped. This means that somebody could come back later and confirm
        the subscription. Sorry. Blame Amazon."
    required: False
    default: True
  platform:
    description:
      - "Name of the push platform your platform app will connect to, e.g. APNS"
    required: False
    default: None
  platform_app_attributes:
    description:
      - "Any necessary platform app attributes - see AWS documentation
        at http://docs.aws.amazon.com/sns/latest/api/API_SetPlatformApplicationAttributes.html"
    required: False
    default: None
  token:
    description:
      - "Push token - only required for creating platform endpoints"
    required: False
    default: None
  endpoint_attributes:
    description:
      - "Any necessary platform endpoint attributes - see AWS documentation
        at http://docs.aws.amazon.com/sns/latest/api/API_SetEndpointAttributes.html"
    required: False
    default: None
extends_documentation_fragment: aws
requirements: [ "boto" ]
"""

EXAMPLES = """

- name: Create alarm SNS topic
  sns_topic:
    name: "alarms"
    state: present
    display_name: "alarm SNS topic"
    delivery_policy:
      http:
        defaultHealthyRetryPolicy:
            minDelayTarget: 2
            maxDelayTarget: 4
            numRetries: 3
            numMaxDelayRetries: 5
            backoffFunction: "<linear|arithmetic|geometric|exponential>"
        disableSubscriptionOverrides: True
        defaultThrottlePolicy:
            maxReceivesPerSecond: 10
    subscriptions:
      - endpoint: "my_email_address@example.com"
        protocol: "email"
      - endpoint: "my_mobile_number"
        protocol: "sms"

- name: Create SNS endpoint
  sns_management:
  name: example-iOS-push-platform
  state: present
  type: platform_app
  platform: APNS
  platform_app_attributes:
    PlatformPrincipal:  "{{ lookup('file', dev_ssl_cert) }}"
    PlatformCredential: "{{ lookup('file', dev_private_key) }}"
    SuccessFeedbackSampleRate: 100
    SuccessFeedbackRoleArn: arn:aws:iam::{{ aws_account_id }}:role/SNSSuccessFeedback
    FailureFeedbackRoleArn: arn:aws:iam::{{ aws_account_id }}:role/SNSFailureFeedback

"""

RETURN = '''
sns_arn:
    description: The ARN of the topic you are modifying
    type: string
    sample: "arn:aws:sns:us-east-1:123456789012:my_topic_name"

sns_platform_arn:
    description: The ARN of the topic you are modifying
    type: string
    sample: "arn:aws:sns:us-east-1:123456789012:app/my_platform/my_platform_app_name"

sns_endpoint_arn:
    description: The ARN of the topic you are modifying
    type: string
    sample: "arn:aws:sns:us-east-1:123456789012:endpoint/my_platform/my_platform_app_name/my_endpoint_uuid"

sns_topic:
    description: Dict of sns topic details
    type: dict
    sample:
      name: sns-topic-name
      state: present
      display_name: default
      policy: {}
      delivery_policy: {}
      subscriptions_new: []
      subscriptions_existing: []
      subscriptions_deleted: []
      subscriptions_added: []
      subscriptions_purge': false
      check_mode: false
      topic_created: false
      topic_deleted: false
      attributes_set: []
'''

import time
import json
import re

try:
    import boto.sns
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import connect_to_aws, ec2_argument_spec, get_aws_connection_info


class BotoListAllItemsManager:
    """Helper tool to allow us to search through all Topics, PlatformApps,
    or PlatformEndpoints with basically the same code.
    """
    def __init__(self, callback, keyword):
        self.callback = callback
        self.keyword = keyword


class SnsBaseManager(object):
    def __init__(self, name, module, region, **aws_connect_params):
        self.name = name
        self.region = region
        self.module = module
        self.aws_connect_params = aws_connect_params
        self.connection = self._get_boto_connection()
        self.changed = False
        self.check_mode = self.module.check_mode
        # Each key in this map is the name of the method being called, which corresponds to how boto structures the
        # returned values.
        self.item_describer_map = {
            'ListTopics': BotoListAllItemsManager(self.connection.get_all_topics, 'TopicArn'),
            'ListPlatformApplications': BotoListAllItemsManager(
                self.connection.list_platform_applications, 'PlatformApplicationArn'
            ),
            'ListEndpointsByPlatformApplication': BotoListAllItemsManager(
                self.connection.list_endpoints_by_platform_application, 'EndpointArn'
            )
        }
        # Overridden in the subclasses
        self.arn_prefix = None

    def _get_boto_connection(self):
        try:
            return connect_to_aws(boto.sns, self.region,
                                  **self.aws_connect_params)
        except BotoServerError as err:
            self.module.fail_json(msg=err.message)

    def _get_all_items(self, command_name, command_kwargs=None):
        """Generic code to hit paging endpoints of AWS's and collect all the results.

        :param command_name: Name of the search command to run, e.g. ListTopics
        :param command_kwargs: Any additional arguments to pass to the search commands, e.g. filters
        :return: All possible results from the search
        """
        if not command_name in self.item_describer_map:
            self.module.fail_json('Unknown command failure, attempted unfamiliar command {}'.format(command_name))
        if command_kwargs is None:
            command_kwargs = {}
        command = self.item_describer_map[command_name].callback

        # These keywords are determined by boto's return structure
        response_keyword = '{}Response'.format(command_name)
        result_keyword = '{}Result'.format(command_name)

        next_token = None
        results = []
        while True:
            try:
                response = command(next_token=next_token, **command_kwargs)
            except BotoServerError as err:
                self.module.fail_json(msg=err.message)
            # All of these calls return NextToken and the list of requested things, that's it
            other_key = filter(lambda x: x != 'NextToken', response[response_keyword][result_keyword].keys())[0]
            results.extend(response[response_keyword][result_keyword][other_key])
            next_token = response[response_keyword][result_keyword]['NextToken']
            if not next_token:
                break
        return results

    def _select_item_matching_arn_string(self, command_name):
        """Find the item of a certain type with an ARN structure matching `self.name` and `self.arn_prefix` fields

        :param command_name: Name of the search command to run, e.g. ListTopics
        :return: Full item dict corresponding to the item with the desired ARN
        """
        # topic names cannot have colons, so this captures the full topic name
        all_items = self._get_all_items(command_name=command_name)
        arn_keyword = '{}{}'.format(self.arn_prefix, self.name)
        for item in all_items:
            if item[self.item_describer_map[command_name].keyword].endswith(arn_keyword):
                return item


class SnsPlatformManager(SnsBaseManager):
    """ Handles SNS Platform creation and destruction """
    def __init__(self, module, region, name, platform, attributes, **aws_connect_params):
        super(SnsPlatformManager, self).__init__(name, module, region, **aws_connect_params)
        self.platform = platform
        self.attributes = attributes
        self.app = None # Cache the PlatformApplication info if/once we create it
        self.modified_endpoint = None # Endpoint we've modified, if any,
        self.arn_prefix = ':app/{}/'.format(platform)

    def module_args(self):
        my_app = self.ensure_platform_app()
        # Don't include platform attributes, as they are private keys and ssl certs and the like.
        args_dict = {
            'sns_platform_arn': my_app['PlatformApplicationArn']
        }
        if self.modified_endpoint:
            # Don't include token.
            args_dict.update({
                'sns_endpoint_arn': self.modified_endpoint['EndpointArn'],
                'sns_endpoint_enabled': self.modified_endpoint['Attributes']['Enabled'],
                'sns_endpoint_user_data': self.modified_endpoint['Attributes']['CustomUserData']
            })
        return args_dict

    def _create_platform_app(self):
        if not self.module.check_mode:
            create_platform_response = self.connection.create_platform_application(
                name=self.name, platform=self.platform, attributes=self.attributes
            )['CreatePlatformApplicationResponse']['CreatePlatformApplicationResult']
            attributes = self.connection.get_platform_application_attributes(
                create_platform_response['PlatformApplicationArn']
            )['GetPlatformApplicationAttributesResponse']['GetPlatformApplicationAttributesResult']
            return {
                'PlatformApplicationArn': create_platform_response['PlatformApplicationArn'],
                'Attributes': attributes
            }
        else:
            return {'PlatformApplicationArn': 'successfulArn', 'Attributes': {}}

    def check_for_existing_platform_app(self):
        return self._select_item_matching_arn_string('ListPlatformApplications')

    def ensure_platform_app(self):
        if self.app:
            return self.app
        existing_app = self.check_for_existing_platform_app()
        if not existing_app:
            existing_app = self._create_platform_app()
            self.changed = True
        else:
            existing_app_attributes = existing_app.get('Attributes', existing_app.get('attributes'))
            if self.attributes != existing_app_attributes:
                self.connection.set_platform_application_attributes(
                    platform_application_arn=existing_app['PlatformApplicationArn'],
                    attributes=self.attributes
                )
                self.changed = True
        self.app = existing_app
        return existing_app

    def delete_platform_app(self):
        existing_app = self.check_for_existing_platform_app()
        if not existing_app:
            return
        else:
            self.connection.delete_platform_application(
                platform_application_arn=existing_app['PlatformApplicationArn']
            )

    def _create_platform_endpoint(self, token, endpoint_attributes):
        this_app = self.ensure_platform_app()
        return self.connection.create_platform_endpoint(
            platform_application_arn=this_app['PlatformApplicationArn'],
            token=token,
            custom_user_data=endpoint_attributes.get('CustomUserData'),
            attributes=endpoint_attributes
        )['CreatePlatformEndpointResponse']['CreatePlatformEndpointResult']['EndpointArn']

    def check_for_platform_endpoint(self, token):
        this_app = self.ensure_platform_app()
        all_endpoints = self._get_all_items(
            'ListEndpointsByPlatformApplication',
            command_kwargs={
                'platform_application_arn': this_app['PlatformApplicationArn']
            }
        )
        for endpoint in all_endpoints:
            if endpoint['Attributes']['Token'] == token:
                return endpoint
        return None

    def ensure_platform_endpoint(self, token, endpoint_attributes):
        existing_endpoint = self.check_for_platform_endpoint(token)
        if not existing_endpoint:
            existing_endpoint = self._create_platform_endpoint(token, endpoint_attributes)
            self.module.changed = True
            self.modified_endpoint = existing_endpoint
        else:
            if not existing_endpoint['Attributes'] == endpoint_attributes:
                self.connection.set_endpoint_attributes(
                    endpoint_arn=existing_endpoint['EndpointArn'],
                    attributes=endpoint_attributes
                )
                self.modified_endpoint = existing_endpoint
                self.modified_endpoint['Attributes'] = endpoint_attributes
        return existing_endpoint

    def delete_platform_endpoint(self, token):
        existing_app = self.check_for_existing_platform_app()
        if not existing_app:
            return
        existing_endpoint = self.check_for_platform_endpoint(token)
        if not existing_endpoint:
            return
        else:
            self.connection.delete_endpoint(
                endpoint_arn=existing_endpoint['EndpointArn']
            )


class SnsTopicManager(SnsBaseManager):
    """ Handles SNS Topic creation and destruction """

    def __init__(self,
                 module,
                 name,
                 state,
                 display_name,
                 policy,
                 delivery_policy,
                 subscriptions,
                 purge_subscriptions,
                 region,
                 **aws_connect_params):

        super(SnsTopicManager, self).__init__(name, module, region, **aws_connect_params)

        self.state = state
        self.display_name = display_name
        self.policy = policy
        self.delivery_policy = delivery_policy
        self.subscriptions = subscriptions
        self.subscriptions_existing = []
        self.subscriptions_deleted = []
        self.subscriptions_added = []
        self.purge_subscriptions = purge_subscriptions
        self.topic_created = False
        self.topic_deleted = False
        self.arn_topic = None
        self.attributes_set = []
        self.arn_prefix = ':'

    def _arn_topic_lookup(self):
        topic = self._select_item_matching_arn_string(command_name='ListTopics')
        return topic['TopicArn']

    def _create_topic(self):
        self.changed = True
        self.topic_created = True
        if not self.check_mode:
            self.connection.create_topic(self.name)
            self.arn_topic = self._arn_topic_lookup()
            while not self.arn_topic:
                time.sleep(3)
                self.arn_topic = self._arn_topic_lookup()

    def _set_topic_attrs(self):
        topic_attributes = self.connection.get_topic_attributes(self.arn_topic) \
            ['GetTopicAttributesResponse'] ['GetTopicAttributesResult'] \
            ['Attributes']

        if self.display_name and self.display_name != topic_attributes['DisplayName']:
            self.changed = True
            self.attributes_set.append('display_name')
            if not self.check_mode:
                self.connection.set_topic_attributes(self.arn_topic, 'DisplayName',
                    self.display_name)

        if self.policy and self.policy != json.loads(topic_attributes['Policy']):
            self.changed = True
            self.attributes_set.append('policy')
            if not self.check_mode:
                self.connection.set_topic_attributes(self.arn_topic, 'Policy',
                    json.dumps(self.policy))

        if self.delivery_policy and ('DeliveryPolicy' not in topic_attributes or \
           self.delivery_policy != json.loads(topic_attributes['DeliveryPolicy'])):
            self.changed = True
            self.attributes_set.append('delivery_policy')
            if not self.check_mode:
                self.connection.set_topic_attributes(self.arn_topic, 'DeliveryPolicy',
                    json.dumps(self.delivery_policy))

    def _canonicalize_endpoint(self, protocol, endpoint):
        if protocol == 'sms':
            return re.sub('[^0-9]*', '', endpoint)
        return endpoint

    def _get_topic_subs(self):
        next_token = None
        while True:
            response = self.connection.get_all_subscriptions_by_topic(self.arn_topic, next_token)
            self.subscriptions_existing.extend(response['ListSubscriptionsByTopicResponse'] \
                ['ListSubscriptionsByTopicResult']['Subscriptions'])
            next_token = response['ListSubscriptionsByTopicResponse'] \
                ['ListSubscriptionsByTopicResult']['NextToken']
            if not next_token:
                break

    def _set_topic_subs(self):
        subscriptions_existing_list = []
        desired_subscriptions = [(sub['protocol'],
            self._canonicalize_endpoint(sub['protocol'], sub['endpoint'])) for sub in
            self.subscriptions]

        if self.subscriptions_existing:
            for sub in self.subscriptions_existing:
                sub_key = (sub['Protocol'], sub['Endpoint'])
                subscriptions_existing_list.append(sub_key)
                if self.purge_subscriptions and sub_key not in desired_subscriptions and \
                    sub['SubscriptionArn'] != 'PendingConfirmation':
                    self.changed = True
                    self.subscriptions_deleted.append(sub_key)
                    if not self.check_mode:
                        self.connection.unsubscribe(sub['SubscriptionArn'])

        for (protocol, endpoint) in desired_subscriptions:
            if (protocol, endpoint) not in subscriptions_existing_list:
                self.changed = True
                self.subscriptions_added.append(sub)
                if not self.check_mode:
                    self.connection.subscribe(self.arn_topic, protocol, endpoint)

    def _delete_subscriptions(self):
        # NOTE: subscriptions in 'PendingConfirmation' timeout in 3 days
        #       https://forums.aws.amazon.com/thread.jspa?threadID=85993
        for sub in self.subscriptions_existing:
            if sub['SubscriptionArn'] != 'PendingConfirmation':
                self.subscriptions_deleted.append(sub['SubscriptionArn'])
                self.changed = True
                if not self.check_mode:
                    self.connection.unsubscribe(sub['SubscriptionArn'])

    def _delete_topic(self):
        self.topic_deleted = True
        self.changed = True
        if not self.check_mode:
            self.connection.delete_topic(self.arn_topic)

    def ensure_ok(self):
        self.arn_topic = self._arn_topic_lookup()
        if not self.arn_topic:
            self._create_topic()
        self._set_topic_attrs()
        self._get_topic_subs()
        self._set_topic_subs()

    def ensure_gone(self):
        self.arn_topic = self._arn_topic_lookup()
        if self.arn_topic:
           self._get_topic_subs()
           if self.subscriptions_existing:
               self._delete_subscriptions()
           self._delete_topic()

    def get_info(self):
        info = {
            'name': self.name,
            'state': self.state,
            'display_name': self.display_name,
            'policy': self.policy,
            'delivery_policy': self.delivery_policy,
            'subscriptions_new': self.subscriptions,
            'subscriptions_existing': self.subscriptions_existing,
            'subscriptions_deleted': self.subscriptions_deleted,
            'subscriptions_added': self.subscriptions_added,
            'subscriptions_purge': self.purge_subscriptions,
            'check_mode': self.check_mode,
            'topic_created': self.topic_created,
            'topic_deleted': self.topic_deleted,
            'attributes_set': self.attributes_set
        }

        return info


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present',
                'absent']),
            display_name=dict(type='str', required=False),
            policy=dict(type='dict', required=False),
            delivery_policy=dict(type='dict', required=False),
            subscriptions=dict(default=[], type='list', required=False),
            purge_subscriptions=dict(type='bool', default=True),
            type=dict(type='str', default='topic'),
            platform=dict(type='str', required=False),
            platform_app_attributes=dict(type='dict', required=False),
            token=dict(type='str', required=False),
            endpoint_attributes=dict(type='dict', required=False)
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    name = module.params.get('name')
    state = module.params.get('state')
    display_name = module.params.get('display_name')
    policy = module.params.get('policy')
    delivery_policy = module.params.get('delivery_policy')
    subscriptions = module.params.get('subscriptions')
    purge_subscriptions = module.params.get('purge_subscriptions')
    type = module.params.get('type')
    platform = module.params.get('platform')
    platform_app_attributes = module.params.get('platform_app_attributes')
    token = module.params.get('token')
    endpoint_attributes = module.params.get('endpoint_attributes')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)
    if not region:
        module.fail_json(msg="region must be specified")

    if type == 'topic':
        sns_topic = SnsTopicManager(module,
                                    name,
                                    state,
                                    display_name,
                                    policy,
                                    delivery_policy,
                                    subscriptions,
                                    purge_subscriptions,
                                    region,
                                    **aws_connect_params)

        if state == 'present':
            sns_topic.ensure_ok()

        elif state == 'absent':
            sns_topic.ensure_gone()

        sns_facts = dict(changed=sns_topic.changed,
                         sns_arn=sns_topic.arn_topic,
                         sns_topic=sns_topic.get_info())

        module.exit_json(**sns_facts)
    elif type == 'platform_app':
        sns_platform = SnsPlatformManager(
            module, region, name, platform, platform_app_attributes, **aws_connect_params
        )
        if state == 'present':
            sns_platform.ensure_platform_app()
        elif state == 'absent':
            sns_platform.delete_platform_app()
        module.exit_json(changed=sns_platform.changed, **sns_platform.module_args())
    elif type == 'platform_endpoint':
        sns_platform = SnsPlatformManager(
            module, region, name, platform, platform_app_attributes, **aws_connect_params
        )
        if state == 'present':
            sns_platform.ensure_platform_endpoint(token, endpoint_attributes)
        elif state == 'absent':
            sns_platform.delete_platform_endpoint(token)
        module.exit_json(changed=sns_platform.changed, **sns_platform.module_args())
    else:
        module.fail_json(msg='Unknown sns object type {} with name {}'.format(type, name))


if __name__ == '__main__':
    main()