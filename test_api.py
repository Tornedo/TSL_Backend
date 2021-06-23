import json
import unittest

import app


class TestFlaskApi(unittest.TestCase):

    def setUp(self):
        self.app = app.app.test_client()
        self.app.testing = True
        app.init_db()

    def test_register(self):
        payload = dict(
            username='test-user',
            password='test-pass'
        )
        res = self.app.post('/api/users', data=json.dumps(payload), content_type='application/json')
        assert res.status_code == 201
        expected = {'username': payload['username']}
        assert expected == json.loads(res.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
