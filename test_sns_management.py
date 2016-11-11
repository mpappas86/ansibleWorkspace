import mock
from moto import mock_sns
from moto.sns.models import PlatformEndpoint
import unittest

from sns_management import SnsTopicManager, SnsPlatformManager


class MockModule(object):
    check_mode = False

    def fail_json(self, *args, **kwargs):
        raise Exception(str(args) + str(kwargs))

    def exit_json(self, *args, **kwargs):
        return


# Moto currently doesn't auto-update the attributes of an endpoint, so it doesn't add the token you passed
# in to the list of attributes without you manually intervening to do so.
# See the PR to fix this here: https://github.com/spulec/moto/pull/763
def patch_moto_wrapper(*a, **k):
    endpoint = PlatformEndpoint(*a, **k)
    if not 'Token' in endpoint.attributes:
        endpoint.attributes['Token'] = endpoint.token
    return endpoint


@mock_sns
class AnsibleSNSManagementPlatformTests(unittest.TestCase):
    def setUp(self):
        self.platform_manager = SnsPlatformManager(
            MockModule(),
            'us-east-1',
            'fakeappname',
            'APNS',
            {
                'PlatformPrincipal': 'foo',
                'PlatformCredential': 'bar'
            },
            aws_access_key_id=None,
            aws_secret_access_key=None
        )

        self.fake_push_token = 'foobar'

    def tearDown(self):
        # Ensure no active platform app after tests.
        self.platform_manager.delete_platform_endpoint(token=self.fake_push_token)
        self.platform_manager.delete_platform_app()

    def testCreatePlatform(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()

    def testDestroyPlatform(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.delete_platform_app()
        assert not self.platform_manager.check_for_existing_platform_app()

    def testRecreatePlatform(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()
        assert self.platform_manager.changed
        self.platform_manager.changed = False
        # Clear the cache, so to speak. Don't want it not trying to create the app at all!
        self.platform_manager.app = None

        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()
        assert not self.platform_manager.changed

    def testCreateEndpoint(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()

        with mock.patch('moto.sns.models.PlatformEndpoint', wraps=patch_moto_wrapper):
            assert not self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)
            self.platform_manager.ensure_platform_endpoint(
                token=self.fake_push_token, endpoint_attributes={'CustomUserData': 'fooey'}
            )
            assert self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)

    def testDestroyEndpoint(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()

        with mock.patch('moto.sns.models.PlatformEndpoint', wraps=patch_moto_wrapper):
            assert not self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)
            self.platform_manager.ensure_platform_endpoint(
                token=self.fake_push_token, endpoint_attributes={'CustomUserData': 'fooey'}
            )
            assert self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)

            self.platform_manager.delete_platform_endpoint(token=self.fake_push_token)
            assert not self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)

    def testRecreateEndpoint(self):
        assert not self.platform_manager.check_for_existing_platform_app()
        self.platform_manager.ensure_platform_app()
        assert self.platform_manager.check_for_existing_platform_app()

        with mock.patch('moto.sns.models.PlatformEndpoint', wraps=patch_moto_wrapper):
            assert not self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)
            self.platform_manager.ensure_platform_endpoint(
                token=self.fake_push_token, endpoint_attributes={'CustomUserData': 'fooey'}
            )
            assert self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)
            assert self.platform_manager.changed
            self.platform_manager.changed = False
            self.platform_manager.modified_endpoint = None

            self.platform_manager.ensure_platform_endpoint(
                token=self.fake_push_token, endpoint_attributes={'CustomUserData': 'fooey'}
            )
            assert self.platform_manager.check_for_platform_endpoint(token=self.fake_push_token)
            assert not self.platform_manager.changed






