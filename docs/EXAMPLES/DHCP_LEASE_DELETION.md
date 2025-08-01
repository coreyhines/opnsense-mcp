# DHCP Lease Deletion

This document describes the DHCP lease deletion functionality in the OPNsense MCP server.

## Overview

The DHCP lease deletion tool allows you to delete DHCP leases from OPNsense by hostname, IP address, or MAC address. This is useful for:

- Removing stale or unwanted DHCP leases
- Forcing devices to request new IP addresses
- Managing network access by removing specific device leases
- Troubleshooting DHCP issues

## API Endpoints

The tool uses the following OPNsense API endpoints:

- **DHCPv4 lease deletion**: `POST /api/dhcpv4/leases/del_lease`
- **DHCPv6 lease deletion**: `POST /api/dhcpv6/leases/del_lease`

Both endpoints require an `ip` parameter containing the IP address to delete.

## Tool Usage

### Tool Name
`dhcp_lease_delete`

### Parameters

The tool accepts one of the following parameters:

- `hostname` (string): Hostname to search for and delete
- `ip` (string): IP address to delete directly
- `mac` (string): MAC address to search for and delete

**Note**: You must provide exactly one of these parameters.

### Examples

#### Delete by IP Address
```json
{
  "name": "dhcp_lease_delete",
  "arguments": {
    "ip": "192.168.1.100"
  }
}
```

#### Delete by Hostname
```json
{
  "name": "dhcp_lease_delete",
  "arguments": {
    "hostname": "my-device"
  }
}
```

#### Delete by MAC Address
```json
{
  "name": "dhcp_lease_delete",
  "arguments": {
    "mac": "aa:bb:cc:dd:ee:ff"
  }
}
```

### Response Format

The tool returns a JSON response with the following structure:

```json
{
  "status": "success",
  "deleted_leases": [
    {
      "ip": "192.168.1.100",
      "mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "my-device",
      "type": "IPv4",
      "status": "deleted"
    }
  ],
  "total_deleted": 1,
  "search_criteria": {
    "hostname": null,
    "ip": "192.168.1.100",
    "mac": null
  }
}
```

### Status Values

- `success`: Leases were successfully deleted
- `no_matches`: No leases matched the search criteria
- `partial_success`: Some leases were deleted, but errors occurred for others
- `error`: An error occurred during the operation

### Error Handling

If errors occur during deletion, they are included in the response:

```json
{
  "status": "partial_success",
  "deleted_leases": [...],
  "total_deleted": 1,
  "errors": [
    "Failed to delete IPv4 lease 192.168.1.101: API Error"
  ],
  "search_criteria": {...}
}
```

## Implementation Details

### MAC Address Normalization

The tool automatically normalizes MAC addresses to handle various formats:

- `aa:bb:cc:dd:ee:ff` (colons)
- `AA-BB-CC-DD-EE-FF` (dashes)
- `aabbccddeeff` (no separators)
- `aa.bb.cc.dd.ee.ff` (dots)

All formats are converted to lowercase with colons for comparison.

### Search Logic

1. **IP Address**: Direct match against lease IP addresses
2. **MAC Address**: Normalized comparison against lease MAC addresses
3. **Hostname**: Case-insensitive comparison against lease hostnames

### IPv4 and IPv6 Support

The tool searches both IPv4 and IPv6 leases and deletes matches from both pools if found.

### Error Recovery

- Individual lease deletion failures don't stop the process
- Each failed deletion is logged and reported
- Successful deletions are still processed even if some fail

## Security Considerations

- Only authenticated users with appropriate API permissions can delete DHCP leases
- The tool requires valid OPNsense API credentials
- Deleted leases will force devices to request new IP addresses
- Consider the impact on network connectivity before deleting leases

## Troubleshooting

### Common Issues

1. **No matches found**: Verify the hostname, IP, or MAC address exists in the DHCP lease table
2. **API errors**: Check API credentials and network connectivity
3. **Permission denied**: Ensure the API user has DHCP management permissions

### Debugging

Enable debug logging to see detailed information about the deletion process:

```bash
export OPNSENSE_DEBUG=1
```

## Related Tools

- `dhcp`: View current DHCP leases
- `arp`: View ARP table for IP/MAC mappings
- `system`: Check system status and services

## Testing

The tool includes comprehensive tests covering:

- MAC address normalization
- Lease matching by different criteria
- Error handling scenarios
- API interaction validation

Run tests with:

```bash
python -m pytest tests/test_dhcp_lease_delete.py -v
``` 
