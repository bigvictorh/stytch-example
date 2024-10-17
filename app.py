import os
import secrets
from flask import Flask, render_template, request, redirect, session, url_for
from authlib.integrations.flask_client import OAuth
from stytch import B2BClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Initialize OAuth with Google (if needed)
# oauth = OAuth(app)
# google = oauth.register(
#     name='google',
#     client_id=os.getenv('GOOGLE_CLIENT_ID'),
#     client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     authorize_params=None,
#     access_token_params=None,
#     refresh_token_url=None,
#     redirect_uri=os.getenv('GOOGLE_REDIRECT_URI'),
#     jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
#     client_kwargs={'scope': 'openid email profile'}
# )

# Initialize Stytch client for B2B
stytch_client = B2BClient(
    project_id=os.getenv('STYTCH_PROJECT_ID'),
    secret=os.getenv('STYTCH_SECRET'),
    environment="test"  # or "live" for production
)

# Routes

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('organizations'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Stytch password login
            resp = stytch_client.passwords.authenticate(
                organization_id=os.getenv('STYTCH_ORG_ID'),
                email=email,
                password=password
            )
            session['user_email'] = email
            session['organizations'] = resp.member['organizations']
            return redirect(url_for('organizations'))
        except Exception as e:
            print('Login failed. Check your credentials and try again.')
    return render_template('login.html')

# # Google Login
# @app.route('/google_login')
# def google_login():
#     # Generate a secure nonce and store it in the session for later validation
#     nonce = secrets.token_urlsafe(16)
#     session['nonce'] = nonce  # Save nonce in session

#     redirect_uri = url_for('google_authorize', _external=True)
#     return google.authorize_redirect(redirect_uri, nonce=nonce)

# # Handle Google OAuth authorization
# @app.route('/google_authorize')
# def google_authorize():
#     token = google.authorize_access_token()

#     # Retrieve the nonce stored in the session
#     nonce = session.pop('nonce', None)

#     # Validate the ID token using the nonce
#     user_info = google.parse_id_token(token, nonce=nonce)
    
#     # Store the user's email in session
#     session['user_email'] = user_info['email']

#     # Check if the user is part of any organizations (using Stytch)
#     organizations_resp = stytch_client.discovery.organizations.list(session_token=user_info['email'])
#     session['organizations'] = organizations_resp['organizations']

#     return redirect(url_for('organizations'))

# Magic Link Discovery
@app.route('/send_magic_link', methods=['POST'])
def send_magic_link():
    email = request.form['email']
    stytch_client.magic_links.email.discovery.send(email_address=email)
    print('Magic link sent to your email.')
    return redirect(url_for('login'))

@app.route('/auth/complete')
def auth_complete():
    token = request.args.get('token')
    print(token)  # Debugging: Check if the token is being received correctly
    try:
        # Authenticate the magic link token to retrieve a discovery session
        stytch_resp = stytch_client.magic_links.discovery.authenticate(
            discovery_magic_links_token=token
        )

        # Store the discovery session token in the session
        session['discovery_session_token'] = stytch_resp.intermediate_session_token

        # Fetch the user's organizations using the discovery session token
        organizations_resp = stytch_client.discovery.organizations.list(
            intermediate_session_token=stytch_resp.intermediate_session_token
        )

        # Convert each DiscoveredOrganization object into a dictionary with necessary fields
        organizations = [
            {
                'organization_id': org.organization.organization_id,
                'organization_name': org.organization.organization_name,
                'organization_slug': org.organization.organization_slug,
                'member_email': org.membership.member.email_address,
                'is_admin': org.membership.member.is_admin,
                'roles': [role.role_id for role in org.membership.member.roles]  # Extract roles
            }
            for org in organizations_resp.discovered_organizations
        ]

        # Store the organizations in the session as a list of dictionaries
        session['organizations'] = organizations

        return redirect(url_for('organizations'))
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return redirect(url_for('login'))

# Display organizations and allow user to select one
@app.route('/organizations')
def organizations():
    if 'discovery_session_token' not in session:
        return redirect(url_for('login'))

    organizations = session.get('organizations', [])
    return render_template('organizations.html', organizations=organizations)

# Handle organization selection and create an intermediate session token
@app.route('/select_organization/<org_id>')
def select_organization(org_id):
    if 'discovery_session_token' not in session:
        return redirect(url_for('login'))

    try:
        # Exchange the discovery session token for an intermediate session token
        intermediate_resp = stytch_client.discovery.intermediate_session.exchange(
            organization_id=org_id,
            session_token=session['discovery_session_token']
        )

        # Store the intermediate session token in the session
        session['intermediate_session_token'] = intermediate_resp['intermediate_session_token']
        return redirect(url_for('create_member_session', org_id=org_id))
    except Exception as e:
        print(f"Failed to select organization: {str(e)}")
        return redirect(url_for('organizations'))

# Create member session token after organization selection
@app.route('/create_member_session/<org_id>')
def create_member_session(org_id):
    if 'intermediate_session_token' not in session:
        return redirect(url_for('login'))

    try:
        # Create a member session token for the selected organization
        member_session_resp = stytch_client.sessions.authenticate(
            intermediate_session_token=session['intermediate_session_token']
        )

        # Store the member session token and organization info in the session
        session['member_session_token'] = member_session_resp['session_token']
        session['organization'] = org_id
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Failed to create member session: {str(e)}")
        return redirect(url_for('organizations'))

# Organization Detail
@app.route('/organization/<org_id>')
def organization_detail(org_id):
    if 'discovery_session_token' not in session:
        return redirect(url_for('login'))

    organizations = session.get('organizations', [])
    organization = next((org for org in organizations if org['organization_id'] == org_id), None)

    if not organization:
        return redirect(url_for('organizations'))

    return render_template('organization_detail.html', organization=organization)

# User dashboard
@app.route('/dashboard')
def dashboard():
    if 'member_session_token' not in session:
        return redirect(url_for('login'))

    organization_id = session.get('organization')
    return render_template('dashboard.html', organization_id=organization_id)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
