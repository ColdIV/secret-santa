# Secret Santa
A small web application which randomly assigns all participants to each other and lets you add some preferences for them to know.

**Note:** To register new users, the admin has to add them to the database (via the admin panel at `/admin`) without a password set. The password will then be set by the first user who tries to login with the given name. This is not secure, but good enough for me right now as I do not want to handle registrations by random bots.

# Setup
    git clone https://github.com/ColdIV/secret-santa.git
    cd secret-santa
    virtualenv env
### Linux
    source env/bin/activate
### Windows
    .\env\Scripts\activate
### Install requirements    
    pip install -r requirements.txt
## Config
Rename `.config.example` to `.config` and add a port and a secret key

# Run
Run the script with `python app.py dev` for development or with `python app.py` for production
