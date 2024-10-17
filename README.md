# Stytch B2B Authentication Example

## Overview
This Flask app demonstrates how to use Stytch's B2B authentication for multi-tenant SaaS platforms. Users log in with magic links and can view all the organizations they belong to, then select one to continue to their dashboard.

## Features
- **Magic Link Authentication**: Users log in via a magic link sent to their email.
- **Multi-Organization View**: After logging in, users can see all organizations they belong to.
- **Secure Session Management**: Stytch’s intermediate and member session tokens ensure secure organization selection and session management.

## How It Works
- **Stytch B2BClient**: Handles authentication via magic links and retrieves the organizations associated with the user.
- **User Flow**:
  1. User requests a magic link via email.
  2. Click the link to log in.
  3. View and select an organization to proceed to the dashboard.

## Future Enhancements
- **Google OAuth**: Initial work is present, but not fully implemented.
- **Organization Details**: Currently basic, with plans to expand to include roles, permissions, and more details.

## Setup Instructions

### 1. Set Up a Virtual Environment
Create and activate a virtual environment to keep your dependencies isolated:

```bash
# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
```

### 2. Install Dependencies
Once your virtual environment is active, install the required dependencies:

```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Create a `.env` file in the project root with the following variables:

```env
STYTCH_PROJECT_ID=your-stytch-project-id
STYTCH_SECRET=your-stytch-secret
SECRET_KEY=your-flask-secret-key
STYTCH_ORG_ID=your-organization-id
```

### 4. Running the App
After setting up your environment and dependencies, you can run the Flask app:

```bash
python3 app.py
```

The app will be available at `127.0.0.1:5000`.

