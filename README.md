# Secret Santa
A small web application which randomly assigns all participants to each other and lets you add some preferences for them to know.

# Setup
    git clone https://github.com/ColdIV/secret-santa.git
    cd drawingboard
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
