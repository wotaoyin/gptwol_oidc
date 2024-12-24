from flask import Flask, request, render_template, redirect, url_for, flash, session # type: ignore
import socket
import struct
import subprocess
import os
import configparser
from authlib.integrations.flask_client import OAuth # type: ignore

port = os.environ.get('PORT', 5000)
ping_timeout = os.environ.get('PING_TIMEOUT', 300)
cron_filename = '/etc/cron.d/gptwol'
computer_filename = 'computers.txt'

app = Flask(__name__, static_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(12)

# -----------------------------------------------------------------------------
# 1) Load OIDC config from oidc.txt. Ensure you limit its permission.
# -----------------------------------------------------------------------------
oidc_parser = configparser.ConfigParser()

# Check environment variables
env_client_id = os.environ.get('CLIENT_ID')
env_client_secret = os.environ.get('CLIENT_SECRET')
env_discovery_url = os.environ.get('DISCOVERY_URL')
env_redirect_uri = os.environ.get('REDIRECT_URI')

# If *all* env vars exist, use them directly
if all([env_client_id, env_client_secret, env_discovery_url, env_redirect_uri]):
    client_id = env_client_id
    client_secret = env_client_secret
    discovery_url = env_discovery_url
    redirect_uri = env_redirect_uri
else:
    # Otherwise, read from 'oidc.txt' and override with env vars if set
    # CLIENT_ID, CLIENT_SECRET, DISCOVERY_URL, and REDIRECT_URI must all be set for you to skip reading oidc.txt
    # Environment variables take precedence over the corresponding entries in oidc.txt.
    oidc_parser.read('oidc.txt')
    
    client_id = env_client_id or oidc_parser['openid']['client_id']
    client_secret = env_client_secret or oidc_parser['openid']['client_secret']
    discovery_url = env_discovery_url or oidc_parser['openid']['discovery_url']
    redirect_uri = env_redirect_uri or oidc_parser['openid']['redirect_uri']

# -----------------------------------------------------------------------------
# 2) Configure Authlib OIDC
# -----------------------------------------------------------------------------
oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url=discovery_url,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# -----------------------------------------------------------------------------
# Helper: Get current user email from session
# -----------------------------------------------------------------------------
def get_current_user_email():
    """Return the user’s email address from the session, or None if not logged in."""
    if 'user' in session:
        return session['user'].get('email')
    return None

# -----------------------------------------------------------------------------
# 3) Read/Write user-specific data from computers.txt (INI style)
# -----------------------------------------------------------------------------
def load_user_computers_and_flags(user_email):
    """
    Load the list of computers for the given user_email from 'computers.txt'
    which is used as an INI file with [user_email] sections.
    Also loads 'hide_details' and 'cannot_add_computer' flags.
    Returns (user_computers, user_hide_details, user_cannot_add_computer).
    """
    config = configparser.ConfigParser()
    config.optionxform = str
    if not os.path.exists(computer_filename):
        open(computer_filename, 'w').close()
    config.read(computer_filename)

    if user_email not in config:
        config.add_section(user_email)
        with open(computer_filename, 'w') as f:
            config.write(f)

    # Default values if not specified
    user_hide_details = False
    user_cannot_add_computer = False

    # Read the booleans if present
    if config.has_option(user_email, "hide_details"):
        user_hide_details = config.getboolean(user_email, "hide_details")

    if config.has_option(user_email, "cannot_add_computer"):
        user_cannot_add_computer = config.getboolean(user_email, "cannot_add_computer")

    # Load user computers
    user_computers = []
    for key, value in config.items(user_email):
        # Skip special flags
        if key in ("hide_details", "cannot_add_computer"):
            continue

        line = value.strip()
        fields = line.split(',')
        if len(fields) < 4:
            continue
        name, mac, ip, test_type = fields[0], fields[1], fields[2], fields[3]
        user_computers.append({
            'name': name,
            'mac_address': mac,
            'ip_address': ip,
            'test_type': test_type
        })

    return user_computers, user_hide_details, user_cannot_add_computer

def save_user_computers(user_email, user_computers,
                        user_hide_details=False, user_cannot_add_computer=False):
    """
    Save the given user_computers list plus the boolean flags to computers.txt (INI style).
    Overwrites the entire user section with new lines.
    """
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(computer_filename)

    if config.has_section(user_email):
        config.remove_section(user_email)
    config.add_section(user_email)

    # Store the two flags in the user’s section
    config.set(user_email, "hide_details", str(user_hide_details).lower())
    config.set(user_email, "cannot_add_computer", str(user_cannot_add_computer).lower())

    # Write each computer as key-value pairs
    for idx, comp in enumerate(user_computers):
        line_value = f"{comp['name']},{comp['mac_address']},{comp['ip_address']},{comp['test_type']}"
        config.set(user_email, f"comp{idx}", line_value)

    with open(computer_filename, 'w') as f:
        config.write(f)
        
# -----------------------------------------------------------------------------
# WOL logic, referencing user-based data
# -----------------------------------------------------------------------------
def send_wol_packet(mac_address):
    # Convert the MAC address to a packed binary string
    packed_mac = struct.pack('!6B', *[int(x, 16) for x in mac_address.split(':')])
    # Create a socket and send the WOL packet
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(b'\xff' * 6 + packed_mac * 16, ('<broadcast>', 9))

def is_computer_awake(ip_address, port, timeout=ping_timeout):
    if not port or port.lower() == 'icmp':
        return is_computer_awake_icmp(ip_address)
    else:
        port_int = int(port)
        return is_computer_awake_tcp(ip_address, port_int)

def is_computer_awake_icmp(ip_address, timeout=ping_timeout):
    # Use the ping command (fping) with a timeout
    result = subprocess.run(['fping', '-t', str(timeout), '-c', '1', ip_address],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return (result.returncode == 0)

def is_computer_awake_tcp(ip_address, port, timeout=ping_timeout):
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False

def search_computers(computers, query):
    query = query.lower()
    return [c for c in computers if (query in c['name'].lower() 
                                     or query in c['mac_address'].lower() 
                                     or query in c['ip_address'].lower())]

def initial_computer_status(ip_address, test_type):
    return "asleep"

# -----------------------------------------------------------------------------
# Minimal OIDC routes
# -----------------------------------------------------------------------------
@app.route('/login')
def login():
    if get_current_user_email():
        # already logged in
        return redirect(url_for('wol_form'))
    redirect_uri = url_for('oidc_callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)

@app.route('/oidc/callback')
def oidc_callback():
    token = oauth.oidc.authorize_access_token()
    user_info = token.get('userinfo')
    if not user_info:
        return '''
            <script>
            alert("OIDC: No userinfo found in token.");
            window.location.href = "/";
            </script>
        '''
    # Store user info in the session
    session['user'] = user_info
    return redirect(url_for('wol_form'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('wol_form'))

# -----------------------------------------------------------------------------
# WOL routes (slightly modified to support user-based computers)
# -----------------------------------------------------------------------------
@app.route('/')
def wol_form():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    query = request.args.get('query')
    user_computers, user_hide_details, user_cannot_add_computer = load_user_computers_and_flags(user_email)

    # If there's a search query
    if query:
        user_computers = search_computers(user_computers, query)

    return render_template('wol_form.html',
                           user_email=user_email,
                           computers=user_computers,
                           query=query,
                           user_hide_details=user_hide_details,
                           user_cannot_add_computer=user_cannot_add_computer,
                           is_computer_awake=initial_computer_status,
                           os=os)

@app.route('/delete_computer', methods=['POST'])
def delete_computer():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    name = request.form['name']
    # Load existing data
    user_computers, user_hide_details, user_cannot_add_computer = load_user_computers_and_flags(user_email)

    # Find the mac address for cron removal
    mac_address = None
    for c in user_computers:
        if c['name'] == name:
            mac_address = c['mac_address']
            break

    # Remove from user_computers
    user_computers = [c for c in user_computers if c['name'] != name]

    # Save
    save_user_computers(user_email, user_computers,
                        user_hide_details, user_cannot_add_computer)

    # remove from cron
    if mac_address:
        delete_cron_entry(mac_address)

    return redirect(url_for('wol_form'))

@app.route('/add_computer', methods=['POST'])
def add_computer():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    name = request.form['name']
    mac_address = request.form['mac_address']
    ip_address = request.form['ip_address']
    test_type = request.form['test_type']

    # Load existing data
    user_computers, user_hide_details, user_cannot_add_computer = load_user_computers_and_flags(user_email)

    # If the user is not allowed to add computers, just redirect or show an alert
    if user_cannot_add_computer:
        flash("You are not allowed to add computers", "danger")
        return redirect(url_for('wol_form'))

    # Check if the computer name already exists
    if check_name_exist(name, user_computers):
        flash("Computer name already exists", "danger")
        return redirect(url_for('wol_form'))

    # Add the new computer
    user_computers.append({
        'name': name,
        'mac_address': mac_address,
        'ip_address': ip_address,
        'test_type': test_type
    })
    # Save them back
    save_user_computers(user_email, user_computers,
                        user_hide_details, user_cannot_add_computer)

    return redirect(url_for('wol_form'))

@app.route('/add_cron', methods=['POST'])
def add_cron():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    request_mac_address = request.form['mac_address']
    request_cron = request.form['cron_request']
    cron_command = f"{request_cron} root /usr/local/bin/wakeonlan {request_mac_address}"
    with open(cron_filename, "a") as f:
        f.write(f"{cron_command}\n")
    return redirect(url_for('wol_form'))

@app.route('/delete_cron', methods=['POST'])
def delete_cron():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    request_mac_address = request.form['mac_address']
    delete_cron_entry(request_mac_address)
    return redirect(url_for('wol_form'))

def delete_cron_entry(request_mac_address):
    if not os.path.exists(cron_filename):
        open(cron_filename, 'w').close()
    with open(cron_filename, 'r') as f:
        lines = f.readlines()

    new_lines = []
    deleted = False
    for line in lines:
        if line.startswith('#'):
            new_lines.append(line)
        else:
            fields = line.strip().split()
            if len(fields) < 7:
                new_lines.append(line)
                continue
            # schedule = ' '.join(fields[:5])  # not used directly
            # user = fields[5]                # not used directly
            command = ' '.join(fields[6:])
            mac_address = command.split()[-1]
            if mac_address == request_mac_address:
                deleted = True
            else:
                new_lines.append(line)

    if deleted:
        with open(cron_filename, 'w') as f:
            f.writelines(new_lines)
    # We return a redirect in the route, so here we just finish.

@app.route('/check_status')
def check_status():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    ip_address = request.args.get('ip_address')
    test_type = request.args.get('test_type')
    if is_computer_awake(ip_address, test_type):
        return 'awake'
    else:
        return 'asleep'

@app.route('/check_name_exist')
def check_name_exist(name, user_computers):
    for comp in user_computers:
        if comp['name'] == name:
            return True
    return False

@app.route('/wakeup', methods=['POST'])
def wol_send():
    user_email = get_current_user_email()
    if not user_email:
        return redirect(url_for('login'))

    mac_address = request.form['mac_address']
    user_computers, user_hide_details, user_cannot_add_computer = load_user_computers_and_flags(user_email)
    computer = next((c for c in user_computers if c['mac_address'] == mac_address), None)
    if not computer:
        return '''
        <script>
            alert("Computer not found.");
            window.history.back();
        </script>
        '''
    ip_address = computer['ip_address']
    test_type = computer['test_type']

    if is_computer_awake(ip_address, test_type):
        flash("Computer is Already Awake", "warning")
    else:
        send_wol_packet(mac_address)
        flash("Magic Packet Sent!", "success")

    return redirect(url_for('wol_form'))

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)

