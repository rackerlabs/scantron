"""
Various utility methods.
"""
# Standard Python libraries.
import ipaddress
import time

# Third party Python libraries.
from requests_toolbelt.utils import dump

# Custom Python libraries.


def debug_requests_response(response):
    """Provide debug print info for a requests response object."""

    data = dump.dump_all(response)
    print(data.decode("utf-8"))


def get_timestamp():
    """Generates a timestamp."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)

    return timestamp


def get_iso_8601_timestamp_no_second():
    """Generates an ISO 8601 standardized timestamp.
    https://en.wikipedia.org/wiki/ISO_8601"""

    now = time.localtime()
    timestamp = time.strftime("%Y-%m-%dT%H:%M", now)

    return timestamp


def expand_range_of_ips(start_ip, end_ip):
    """Takes an IP range and returns all the IPs in that range.
    # http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
    """

    ip_range = []

    if (ipaddress.ip_address(start_ip).version == 6) or (ipaddress.ip_address(end_ip).version == 6):
        print("IPv6 IP range not supported in this function: {} - {}".format(start_ip, end_ip))
        return ip_range

    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range


def http_status_code(http_code):
    """Contains a database of all known HTTP status codes and their corresponding plain text description.  For use in
    both program output as well as parsing for specific issue types.

    Args:
        http_code (int): A number containing the HTTP status code to lookup

    Returns:
        string: Returns a description of the status code.
    """

    http_codes = {
        200: "OK",
        201: "OK: Created",
        202: "OK: Accepted",
        203: "OK: Non-Authoritative Information",
        204: "OK: No Content",
        205: "OK: Reset Content",
        206: "OK: Partial Content",
        207: "OK: Multi-Status",
        208: "OK: Already Reported",
        226: "OK: IM Used",
        300: "Redirected: Multiple Choices",
        301: "Redirected: Moved Permanently",
        302: "Redirected: Found",
        303: "Redirected: See Other",
        304: "Redirected: Not Modified",
        305: "Redirected: Use Proxy",
        306: "Redirected: Switch Proxy",
        307: "Redirected: Temporary Redirect",
        308: "Redirected: Permanent Redirect",
        400: "Client Error: Bad Request",
        401: "Client Error: Unauthorized",
        402: "Client Error: Payment Required",
        403: "Client Error: Forbidden",
        404: "Client Error: Not Found",
        405: "Client Error: Method Not Allowed",
        406: "Client Error: Not Acceptable",
        407: "Client Error: Proxy Authentication Required",
        408: "Client Error: Request Timeout",
        409: "Client Error: Conflict",
        410: "Client Error: Gone",
        411: "Client Error: Length Required",
        412: "Client Error: Precondition Failled",
        413: "Client Error: Payload Too Large",
        414: "Client Error: URI Too Large",
        415: "Client Error: Unsupported Media Type",
        416: "Client Error: Range Not Satisfiable",
        417: "Client Error: Expectation Failed",
        418: "Client Error: I'm a teapot",
        421: "Client Error: Misdirected Request",
        422: "Client Error: Un-processable Entity",
        423: "Client Error: Locked",
        424: "Client Error: Failed Dependency",
        426: "Client Error: Upgrade Required",
        428: "Client Error: Precondition Required",
        429: "Client Error: Too Many Requests",
        431: "Client Error: Request Header Fields Too Large",
        440: "Client Error: Login Time-Out",
        444: "Client Error: No Response",
        449: "Client Error: Retry With",
        451: "Client Error: Unavailable For Legal Reasons",
        495: "Client Error: SSL Certificate Error",
        496: "Client Error: SSL Certificate Required",
        497: "Client Error: HTTP Request Sent to HTTPS Port",
        499: "Client Error: Client Closed Request",
        500: "Server Error: Internal Server Error",
        501: "Server Error: Not Implemented",
        502: "Server Error: Bad Gateway",
        503: "Server Error: Service Unavailable",
        504: "Server Error: Gateway Timeout",
        505: "Server Error: HTTP Version Not Supported",
        507: "Server Error: Insufficient Storage",
        508: "Server Error: Loop Detected",
        510: "Server Error: Not Extended",
        511: "Server Error: Network Authentication Required",
        520: "Server Error: Unknown Error when connecting to server behind load balancer",
        521: "Server Error: Web Server behind load balancer is down",
        522: "Server Error: Connection Timed Out to server behind load balancer",
        523: "Server Error: Server behind load balancer is unreachable",
        524: "Server Error: TCP handshake with server behind load balancer completed but timed out",
        525: "Server Error: Load balancer could not negotiate a SSL/TLS handshake with server behind load balancer",
        526: "Server Error: Server behind load balancer returned invalid SSL/TLS cert to load balancer",
        527: "Server Error: Load balancer request timed out/failed after WAN connection was established to origin server",
    }

    http_status = http_codes.get(http_code, "NA")

    return http_status
