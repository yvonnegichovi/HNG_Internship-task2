import unittest
from app import app, db
from models import User, Organisation, OrganisationUsers

class AuthTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Create tables
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_user_registration(self):
        response = self.app.post('/auth/register', json={
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'password123',
            'phone': '1234567890'
        })

        data = response.get_json()
        self.assertEqual(response.status_code, 201)
        self.assertIn('accessToken', data['data'])
        self.assertEqual(data['data']['user']['firstName'], 'John')

    def test_user_login(self):
        self.app.post('/auth/register', json={
            'firstName': 'Jane',
            'lastName': 'Doe',
            'email': 'jane.doe@example.com',
            'password': 'password123',
            'phone': '0987654321'
        })

        response = self.app.post('/auth/login', json={
            'email': 'jane.doe@example.com',
            'password': 'password123'
        })

        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('accessToken', data['data'])

if __name__ == '__main__':
    unittest.main()
