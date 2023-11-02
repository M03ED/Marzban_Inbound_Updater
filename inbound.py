import requests
import logging

# Marzban information
DOMAIN = 'domain.com'  # Replace with your actual domain
PORT = 1234  # Replace with the actual port number
username = 'user' # Replace with your actual username
password = 'pass' # Replace with your actual password

# Inbounds Information
protocol = 'vless' # Replace with your protocol
inbounds_to_remove = ["Vless TCP Inbound"] # Replace with your inbounds list
inbounds_to_add = ["Vless TCP Inbound"] # Replace with your inbounds list
flow = 'xtls-rprx-vision' # Replace with your flow (only works for vless)


def get_access_token(username, password):
    url = f'https://{DOMAIN}:{PORT}/api/admin/token'
    data = {
        'username': username,
        'password': password
    }

    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
        access_token = response.json()['access_token']
        return access_token
    except requests.exceptions.RequestException as e:
        logging.error(f'Error occurred while obtaining access token: {e}')
        return None


def get_users_list(access_token):
    url = f'https://{DOMAIN}:{PORT}/api/users'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        users_list = response.json()
        return users_list
    except requests.exceptions.RequestException as e:
        logging.error(f'Error occurred while retrieving users list: {e}')
        return None


def create_empty_proxy_inbound(user_details, protocol):
    # Create an empty proxy for the specified protocol
    if protocol == "vless":
        user_details['proxies'][protocol] = {
            'flow': flow
        }
    else:
        user_details['proxies'][protocol] = {}

    # Create an empty inbound for the specified protocol
    user_details['inbounds'][protocol] = []


def update_inbounds_for_protocol(username, protocol):
    url = f'https://{DOMAIN}:{PORT}/api/user/{username}'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        user_details = response.json()

        if 'inbounds' in user_details:
            inbounds = user_details['inbounds'].get(protocol, [])
            if inbounds_to_remove:
                updated_inbounds = [inbound for inbound in inbounds if inbound not in inbounds_to_remove]
                user_details['inbounds'][protocol] = updated_inbounds

            if protocol not in user_details['proxies'] or protocol not in user_details['inbounds']:
            # If the protocol is not present, create an empty proxy and inbound
                create_empty_proxy_inbound(user_details, protocol)

            if inbounds_to_add:
                user_details['inbounds'][protocol] += inbounds_to_add

            if user_details['status'] != "disabled":
                user_details['status'] = "active"

            # Create a list of keys to remove
            keys_to_remove = []
            for inbound_protocol in user_details.get('inbounds', {}):
                if not user_details['inbounds'][inbound_protocol]:
                    keys_to_remove.append(inbound_protocol)

            # Remove the keys outside of the loop
            for key in keys_to_remove:
                user_details['inbounds'].pop(key, None)
                user_details['proxies'].pop(key, None)


            # Modify 'links' and 'subscription_url'
            user_details['links'] = []
            user_details['subscription_url'] = ""

            response = requests.put(url, json=user_details, headers=headers)
            response.raise_for_status()
            return True
        else:
            return False

    except requests.exceptions.RequestException as e:
        logging.error(f'Error occurred while removing inbounds for protocol: {e}')
        return False


# Configure logging settings
logging.basicConfig(filename='script_log.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

access_token = get_access_token(username, password)
if access_token:
    users_list = get_users_list(access_token)
    if users_list:
        for user in users_list['users']:
            # Remove specified inbounds for the specified protocol
            if 'inbounds' in user:
                if update_inbounds_for_protocol(user['username'], protocol):
                    print(f"Inbounds updated successfully for user {user['username']} and protocol {protocol}.")
                else:
                    print(f"No specified inbounds found for user {user['username']} and protocol {protocol}.")
        print("All users modified successfully.")    
    else:
        print("Failed to retrieve the users list.")
else:
    print("Failed to obtain the access token.")


