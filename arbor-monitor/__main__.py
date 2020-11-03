from quart import Quart,request
import json, requests, logging, os, argparse, dateutil.parser, datetime
from ipaddress import IPv4Address, IPv4Network
from dis_client_sdk import DisClient


#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

app = Quart(__name__)


@app.route('/dis/sl-webhook',methods=['POST'])
async def process_sightline_webhook_notification():
    """
    This awaits data from Sightline and then parses it into an attack object.
    Once an attack has been finished (ie ongoing is False), the client will
    query Sightline for the attack Source IPs and adds them to the attack object.

    """
    data = await request.data
    payload = json.loads(data)
    payload_data = payload["data"]
    attack_attributes = payload_data["attributes"]
    attack_id = payload_data.get("id")
    logger.debug("Arbor notification payload:" + json.dumps(payload, indent=3))

    if attack_attributes["ongoing"]:
        logger.info(f"Received notification of ONGOING attack (ID: {attack_id})")
    else:
        logger.info(f"Received notification of COMPLETED attack (Attack ID: {attack_id})")

        attack_subobjects = attack_attributes["subobject"]

        start_time = attack_attributes.get("start_time")
        stop_time = attack_attributes.get("stop_time")
        misuse_types = attack_subobjects.get("misuse_types")
        impact_bps = attack_subobjects.get("impact_bps")
        impact_pps = attack_subobjects.get("impact_pps")

        logger.info(f"Attack ID {attack_id}: Misuse Types: {misuse_types}")
        logger.info(f"Attack ID {attack_id}: Start/stop time: {start_time}/{stop_time}")
        logger.debug(f"Attack ID {attack_id}: Impact BPS: {impact_bps}")
        logger.debug(f"Attack ID {attack_id}: Impact PPS: {impact_pps}")

        if args.dry_run:
            logger.info(f"Attack ID {attack_id}: Running in DRY RUN mode - not posting attack")
        else:
            start_timestamp = int(dateutil.parser.isoparse(start_time).timestamp())
            stop_timestamp = int(dateutil.parser.isoparse(stop_time).timestamp())
            logger.debug(f"Attack ID {attack_id}: Start/stop timestamp: {start_timestamp}/{stop_timestamp}")

            dis_event = dis_client.add_attack_event(start_timestamp=start_timestamp,
                                                   end_timestamp=stop_timestamp,
                                                   attack_type=attack_subobjects.get("misuse_types"))

            # Add attributes to the attack event
            dis_client.add_attribute_to_event(event_uuid=dis_event,
                                              name="impact_bps", enum="BPS", value=impact_bps)
            dis_client.add_attribute_to_event(event_uuid=dis_event,
                                              name="impact_pps", enum="PPS", value=impact_pps)
            dis_client.add_attribute_to_event(event_uuid=dis_event,
                                              name="local_attack_id", enum="BIGINT", value=attack_id)
            dis_client.add_attribute_to_event(event_uuid=dis_event,
                                              name="target_host_address", enum="IPV4",
                                              value=attack_subobjects.get("host_address"))
            dis_client.add_attribute_to_event(event_uuid=dis_event,
                                              name="source_boundary", enum="STR",
                                              value=attack_subobjects.get("impact_boundary"))

            # Add the source address info to the event
            source_ip_list = add_source_ips_v2(dis_event, attack_id)

            logger.info(f"Attack ID {attack_id}: Added {len(source_ip_list)} source IPs")
            logger.info(f"Attack ID {attack_id}: Source IPs (first 50): {source_ip_list[0:50]}")

            staged_event_ids = dis_client.get_staged_event_ids()
            logger.info(f"Attack ID {attack_id}: Staged event IDs: {staged_event_ids}")
            # TODO: Add accessor for the DIS client base URL
            logger.info(f"Attack ID {attack_id}: Sending report to DIS server")
            dis_client.send()
            logger.info(f"Attack ID {attack_id}: Report sent to DIS server")

    return 'hello'


def check_sightline_api_supported():
    """
    Checks to ensure the Arbor SP API can be accessed and is a compatible version

    Return:
        True if the API checks out, and False otherwise
    """

    response = requests.get(f"{args.arbor_api_prefix}/api/sp",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    if response.status_code != requests.codes.ok:
        logger.error(f"Error retrieving {response.url}: Status code {response.status_code}")
        return False

    json_response = response.json()
    api_type = json_response['meta']['api']
    api_version = int(json_response['meta']['api_version'])

    if api_type != 'SP':
        logger.error(f"Found unsupported Sightline API (found '{api_type}', expected 'SP'")
        return False

    if api_version < 6:
        logger.error(f"Found unsupported Sightline API version ({api_version} < 6)")
        return False

    logger.info(f"Found Arbor Sightline SP API version {api_version} at {response.url}")

    return True


def send_event(event_object, post_url):
    """
    Sends event to consumer URL.

    Parameters:
    json data to post

    Returns:
    POST request response.

    """
    logger.info(f"POSTing to {post_url}")
    logger.debug(json.dumps(event_object, indent=3))
    r = requests.post(url=post_url, json=event_object, headers={"Content-Type": "application/json"})
    logger.debug("POST response: " + r.text)


def add_source_ips_v1(dis_event, attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id
    dis_client

    Returns:

    The list of source IPs added

    """
    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v6/alerts/{attack_id}/source_ip_addresses",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    json_response = response.json()
    attack_source_ips = json_response['data']['attributes']['source_ips']

    if args.dry_run:
        logger.info(f"Attack ID {attack_id}: Running in DRY RUN mode - not posting attack")

    if dis_client and dis_event:
        for attack_source_ip in attack_source_ips:
            dis_client.add_attack_source_to_event(dis_event, ip=attack_source_ip)
    return attack_source_ips


def add_source_ips_v2(dis_event, attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id
    dis_client

    Returns:

    The list of source IPs added

    """
    ip_list=[]
    # The default for this query is normally 5. So need to make sure to over-ride the default limit
    prefix_query_limit=1000000
    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v6/alerts/{attack_id}/traffic/src_prefixes/"
                            f"?query_unit=bps&query_limit={prefix_query_limit}&query_view=network",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    json_response = response.json()
    for data_elem in json_response['data']:
        elem_id = "unknown"
        try:
            elem_id = data_elem['id']
            logger.debug("Processing network src prefix " + elem_id)
            bps_elem = data_elem['attributes']['view']['network']['unit']['bps']
            elem_name = bps_elem['name']
            elem_max_bps = bps_elem['max_value']
            logger.debug(f"    name: {elem_name}, max bps: {elem_max_bps}")
            net_addr = IPv4Network(elem_name, strict=True)
            if net_addr.prefixlen != 32:
                logger.info(f"Skipping src prefix {elem_id}. Network bitmask is not 32 bits ({elem_name})")
            else:
                ip_addr_str = str(net_addr.network_address)
                if dis_client and dis_event:
                    dis_client.add_attack_source_to_event(dis_event,
                                                          ip=ip_addr_str,
                                                          attribute_list=[
                                                              {
                                                                  "enum": "BPS",
                                                                  "name": "Bytes per second",
                                                                  "value": str(elem_max_bps)
                                                              }])
                ip_list.append(ip_addr_str)
        except Exception as ex:
            logger.info(f"Error processing '{elem_id}': {ex}")

    return ip_list


# MAIN

arg_parser = argparse.ArgumentParser(description='Monitors for Arbor attack events and posts source address reports "'
                                                 'to the specified event consumer')

arg_parser.add_argument ('--debug', "-d,", required=False, action='store_true',
                         default = os.environ.get('DIS_ARBORMON_DEBUG') == "True",
                         help="Enables debugging output/checks")
arg_parser.add_argument ('--dry-run', "-dr,", required=False, action='store_true',
                         default = os.environ.get('DIS_ARBORMON_DRY_RUN') == "True",
                         help="Enables a dry-tun test (doesn't upload to a server - just logs)")
arg_parser.add_argument ('--bind-address', "-a", required=False, action='store', type=str,
                         default=os.environ.get('DIS_ARBORMON_BIND_ADDRESS', "0.0.0.0"),
                         help="specify the address to bind the HTTP/HTTPS server to for receiving "
                              "Arbor SP webhook notifications (or set DIS_ARBORMON_BIND_ADDRESS)")
arg_parser.add_argument ('--bind-port', "-p", required=False, action='store', type=int,
                         default = os.environ.get('DIS_ARBORMON_BIND_PORT', 443),
                         help="specify the port to bind the HTTP/HTTPS server to for receiving "
                              "Arbor SP webhook notifications (or set DIS_ARBORMON_BIND_PORT)")
arg_parser.add_argument ('--cert-chain-file', "-ccf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBORMON_CERT_FILE'),
                         help="the file path containing the certificate chain to use for the "
                              "HTTPS server connection for receiving Arbor SP webhook notifications "
                              "(or set DIS_ARBORMON_CERT_FILE). If not set, only HTTP webhook "
                              "connections will be supported (HTTPS will be disabled).")
arg_parser.add_argument ('--cert-key-file', "-ckf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBORMON_KEY_FILE'),
                         help="the file path containing the key for the associated leaf certificate " 
                              "contained in the certificate chain file for the HTTPS server connection"
                              "for receiving Arbor SP webhook notification (or DIS_ARBORMON_KEY_FILE)")
arg_default = os.environ.get('DIS_ARBORMON_REST_API_PREFIX')
arg_parser.add_argument ('--arbor-api-prefix', "-aap,", required=not arg_default,
                         action='store', type=str, default=arg_default,
                         help="Specify the Arbor API prefix to use for REST calls "
                              "(e.g. 'https://arbor001.acme.com') "
                              "(or set DIS_ARBORMON_REST_API_PREFIX)")
arg_default=os.environ.get('DIS_ARBORMON_REST_API_TOKEN')
arg_parser.add_argument ('--arbor-api-token', "-aat,", required=not arg_default,
                         action='store', type=str, default=arg_default,
                         help="Specify the Arbor API token to use for REST calls "
                              "(or DIS_ARBORMON_REST_API_TOKEN)")
arg_parser.add_argument ('--arbor-api-insecure', "-aai,", required=False,
                         action='store_true', default=False,
                         help="Disable cert checks when invoking Arbor SP API REST calls "
                              "(or DIS_ARBORMON_REST_API_INSECURE)")
arg_parser.add_argument ('--report-consumer-url', "-rcu,", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBORMON_REPORT_CONSUMER_URL'),
                         help="Specifies the API prefix to use for submitting attack reports"
                              "(or DIS_ARBORMON_REPORT_CONSUMER_URL)")
arg_default=os.environ.get('DIS_ARBORMON_REPORT_API_KEY')
arg_parser.add_argument ('--report-consumer-api-key', "-rckey,", required=not arg_default,
                         action='store', type=str, default=arg_default,
                         help="Specify the API key to use for submitting attack reports "
                              "(or DIS_ARBORMON_REPORT_API_KEY)")

args = arg_parser.parse_args()

logging_filename=None
logging_filemode=None
logging.basicConfig (level=(logging.DEBUG if args.debug else logging.INFO),
                     filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger ('dis-arbor-monitor')

cert_chain_filename = args.cert_chain_file.name if args.cert_chain_file else None
cert_key_filename = args.cert_key_file.name if args.cert_key_file else None

logger.info(f"Debug: {args.debug}")
logger.info(f"Dry run: {args.dry_run}")
logger.info(f"Bind address: {args.bind_address}")
logger.info(f"Bind port: {args.bind_port}")
logger.info(f"Cert chain file: {cert_chain_filename}")
logger.info(f"Cert key file: {cert_key_filename}")
logger.info(f"Arbor API prefix: {args.arbor_api_prefix}")
logger.info(f"Arbor API token: {args.arbor_api_token}")
logger.info(f"Consumer URL: {args.report_consumer_url}")
logger.info(f"Consumer API key: {args.report_consumer_api_key}")

if args.dry_run:
    logger.info("RUNNING IN DRY-RUN MODE (not connecting/reporting to the DIS server)")
else:
    dis_client = DisClient(api_key=args.report_consumer_api_key)
    dis_client_info = dis_client.get_info()
    logger.info(f"DIS client name: {dis_client_info.get('name')}")
    org = dis_client_info.get("organization")
    logger.info(f"DIS client organization: {org.get('name') if org else 'Unknown'}")
    logger.info(f"DIS client description: {dis_client_info.get('shortDescription')}")
    logger.info(f"DIS client contact: {org.get('contactEmail')}")
    client_type = dis_client_info.get("clientType")
    logger.info(f"Client type name: {client_type.get('name')}")
    logger.info(f"Client type maker: {client_type.get('maker')}")
    logger.info(f"Client type version: {client_type.get('version')}")
    # TODO: Check the maker (and version?)

if not check_sightline_api_supported():
    logger.error("Exiting due to lack of Arbor SP API support")
    exit(0)

app.run(debug=args.debug, host=args.bind_address, port=args.bind_port,
        certfile=cert_chain_filename, keyfile=cert_key_filename)
