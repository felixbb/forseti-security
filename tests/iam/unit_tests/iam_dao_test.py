# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Unit Tests: Database abstraction objects for IAM Explain. """

from google.apputils import basetest
import uuid
import os

from google.cloud.security.iam.dao import ModelManager, session_creator, create_engine
from google.cloud.security.common.util.threadpool import ThreadPool

def create_test_engine():
    tmpfile = '/tmp/{}.db'.format(uuid.uuid4())
    return create_engine('sqlite:///{}'.format(tmpfile)), tmpfile

class DaoTest(basetest.TestCase):
    """General data abstraction layer use case tests."""

    def setUp(self):
        """Setup."""
        pass

    def test_repr_dao_objects(self):
        """Test __repr__ methods of dao objects."""
        _, data_access = session_creator('test')
        data_access.TBL_BINDING(role_name='role').__repr__()
        data_access.TBL_MEMBER(name='test', type='group').__repr__()
        data_access.TBL_PERMISSION(name='permission').__repr__()
        data_access.TBL_ROLE(name='role').__repr__()
        data_access.TBL_RESOURCE(full_name='full_name', type='test').__repr__()

    def test_explain_granted(self):
        """Test explain_granted."""
        pass

    def test_explain_denied(self):
        """Test explain_denied."""
        pass

    def test_query_access_by_member(self):
        pass

    def test_query_access_by_resource(self):
        pass

    def test_query_permissions_by_roles(self):
        pass

    def test_set_iam_policy(self):
        pass

    def test_get_iam_policy(self):
        pass

    def test_check_iam_policy(self):
        pass

    def test_denormalize(self):
        pass

    def test_list_roles_by_prefix(self):
        pass

    def test_add_role_by_name(self):
        pass

    def test_del_role_by_name(self):
        pass

    def test_add_group_member(self):
        pass

    def test_del_group_member(self):
        pass

    def test_list_group_members(self):
        pass

    def test_list_resources_by_prefix(self):
        pass

    def test_del_resource_by_name(self):
        pass

    def test_add_resource_by_name(self):
        pass

    def test_add_resource(self):
        pass

    def test_add_role(self):
        pass

    def test_add_permission(self):
        pass

    def test_add_binding(self):
        pass

    def test_add_member(self):
        pass

    def test_reverse_expand_members(self):
        pass

    def test_expand_members(self):
        pass

    def test_resolve_resource_ancestors(self):
        pass

    def test_find_resource_path(self):
        pass

    def test_get_roles_by_permission_names(self):
        pass

    def test_get_member(self):
        pass

    def test_expand_resources(self):
        """Expand resource tree."""
        session_maker, data_access = session_creator('test')
        session = session_maker()
        data_access.add_resource_by_name(session, 'res1', '', True)
        data_access.add_resource_by_name(session, 'res2', 'res1', False)
        data_access.add_resource_by_name(session, 'res3', 'res2', False)
        data_access.add_resource_by_name(session, 'res4', 'res3', False)
        data_access.add_resource_by_name(session, 'res5', 'res4', False)
        data_access.add_resource_by_name(session, 'res6', 'res2', False)
        data_access.add_resource_by_name(session, 'res7', 'res6', False)
        data_access.add_resource_by_name(session, 'res8', 'res7', False)
        session.commit()

        self.assertEqual(set(['res{}'.format(i) for i in range(1,9)]),
                         set([r.full_name for r in session.query(data_access.TBL_RESOURCE).all()]),
                         'Expecting all resources to be added to the database')

        def expand(resource):
            return data_access.expand_resources(session, [resource])

        self.assertEqual(set(expand('res1')),
                         set([u'res{}'.format(i) for i in range(1,9)]),
                         'Expecting expansion of res1 to comprise all resources')

        self.assertEqual(set(expand('res2')),
                         set(['res{}'.format(i) for i in range(2,9)]),
                         'Expecting expansion of res2 to comprise all resources but res1')

        self.assertEqual(set(expand('res3')),
                         set(['res3','res4','res5']),
                         'Expecting expansion of res3 to comprise res3,res4 and res5')

        self.assertEqual(set(expand('res8')),
                         set(['res8']),
                         'Expecting expansion of res8 to comprise only res8')
