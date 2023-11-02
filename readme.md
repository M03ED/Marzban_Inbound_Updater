# Marzban Inbounds Updater

First of all set you marzban panel information
```python
DOMAIN = 'domain.com'  # Replace with your actual domain
PORT = 1234  # Replace with the actual port number
username = 'user' # Replace with your actual username
password = 'pass' # Replace with your actual password
```
Then write protocol and inbounds you wanna add or remove (you can write multiple inbound)

```python
protocol = 'vless' # Replace with your protocol
inbounds_to_remove = ["Vless TCP Inbound"] # Replace with your inbounds list
inbounds_to_add = ["Vless TCP Inbound"] # Replace with your inbounds list
flow = 'xtls-rprx-vision' # Replace with your flow (only works for vless)
```
run code and enjoy it