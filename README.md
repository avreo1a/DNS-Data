## Prerequisites
- Python 3.12+
- Wireshark/TShark: `brew install wireshark` (macOS)


Use sudo when going into the venv to allow perms to wireshark
sudo .venv/bin/python server.py



## SQL QUERIES


### Get all DNS queries
SELECT p.*, d.query_name, d.query_type, d.response_code, d.is_response
FROM packets p
JOIN dns_attributes d ON p.id = d.packet_id
WHERE d.query_name IS NOT NULL



### TOP QUERIED DNS

N/A

### FAILED DNS LOOKUPS
N/A