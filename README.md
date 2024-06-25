# panos_api_helper

A simple PAN-OS API helper script for finding firewall rule (security-policy-match).

See also the CLI [`test security-policy-match`](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-cli-quick-start/use-the-cli/test-the-configuration/test-policy-matches.html) command.

## Usage

1. Create `~/.panos/api_key.json`
    ```
    {"ApiKey": "your-api-token"}
    ```

2. Create `~/.panos/fw_urls.json`
    ```
    {
      "fw-group-1": [fw-url1, fw-url2, ...],
      "fw-group-2": [fw-url1, fw-url2, ...]
    }
    ```

3. Install requirements
    ```
    # Optional: create and activate virtualenv
    virtualenv env
    . env/bin/activate

    pip install -r requirements.txt
    ```

4. To find firewall rules that match the given attributes
    ```
    python panos_api_helper.py find-fw-rule SRC_IP DST_IP DST_PORT --fw-group <fw-group-1> --protocol [tcp|udp]
    ```

5. To find user by IP
    ```
    python panos_api_helper.py find-user IP --fw-group <fw-group-1>
    ```
