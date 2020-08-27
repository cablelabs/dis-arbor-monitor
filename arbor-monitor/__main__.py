from quart import Quart,request
import json, requests, logging, os, argparse, dateutil.parser, datetime
from dis_client_sdk import DisClient

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

app = Quart(__name__)


@app.route('/',methods=['POST'])

async def index():
    """
    This awaits data from Arbor and then parses it into an attack object.
    Once an attack has been finished ie ongoing is False, then the code goes back out and queries for
    Source IPs and adds that to the attack object.

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
        attack_source_ips = get_source_ips(attack_id)

        start_time = attack_attributes.get("start_time")
        stop_time = attack_attributes.get("stop_time")
        misuse_types = attack_attributes.get("misuse_types")
        impact_bps = attack_subobjects.get("impact_bps")
        impact_pps = attack_subobjects.get("impact_pps")

        logger.info(f"Attack ID {attack_id}: Misuse Types: {misuse_types}")
        logger.info(f"Attack ID {attack_id}: Start/stop time: {start_time}/{stop_time}")
        logger.debug(f"Attack ID {attack_id}: Impact BPS: {impact_bps}")
        logger.debug(f"Attack ID {attack_id}: Impact PPS: {impact_pps}")
        logger.info(f"Attack ID {attack_id}: Found {len(attack_source_ips)} source IPs")
        logger.info(f"Attack ID {attack_id}: Source IPs (first 50): {attack_source_ips[0:50]}")

        if args.dry_run:
            logger.info(f"Attack ID {attack_id}: Running in DRY RUN mode - not posting attack")
        else:
            start_timestamp = int(dateutil.parser.isoparse(start_time).timestamp())
            stop_timestamp = int(dateutil.parser.isoparse(stop_time).timestamp())
            logger.debug(f"Attack ID {attack_id}: Start/stop timestamp: {start_timestamp}/{stop_timestamp}")

            event_id = dis_client.add_attack_event(start_timestamp=start_timestamp,
                                                   end_timestamp=stop_timestamp,
                                                   attack_type=attack_subobjects.get("misuse_types"))

            # Add attributes to the attack event
            dis_client.add_attribute_to_event(event_uuid=event_id,
                                              name="impact_bps", enum="BPS", value=impact_bps)
            dis_client.add_attribute_to_event(event_uuid=event_id,
                                              name="impact_pps", enum="PPS", value=impact_pps)
            dis_client.add_attribute_to_event(event_uuid=event_id,
                                              name="local_attack_id", enum="BIGINT", value=attack_id)
            dis_client.add_attribute_to_event(event_uuid=event_id,
                                              name="target_host_address", enum="IPV4",
                                              value=attack_subobjects.get("host_address"))
            dis_client.add_attribute_to_event(event_uuid=event_id,
                                              name="source_boundary", enum="STR",
                                              value=attack_subobjects.get("impact_boundary"))

            for attack_source_ip in attack_source_ips:
                # TODO: Test attributes - REMOVE
                dis_client.add_attack_source_to_event(event_id,
                                                      ip=attack_source_ip,
                                                      attribute_list=[
                                                          {
                                                              "enum": "SEVERITY",
                                                              "name": "Severity Level",
                                                              "value": "high"
                                                          },
                                                          {
                                                              "enum": "BPS",
                                                              "name": "Bytes per second",
                                                              "value": "1300"
                                                          }])

            staged_event_ids = dis_client.get_staged_event_ids()
            logger.info(f"Attack ID {attack_id}: Staged event IDs: {staged_event_ids}")
            # TODO: Add accessor for the DIS client base URL
            logger.info(f"Attack ID {attack_id}: Sending report ?? (FIX ME)")
            dis_client.send()
            logger.info(f"Attack ID {attack_id}: Report sent to ?? (FIX ME)")

    return 'hello'

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

def get_source_ips(attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id 

    Returns:

    Array of source IPs

    """

    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v6/alerts/{attack_id}/source_ip_addresses",
                            verify=False,headers={"X-Arbux-APIToken":args.arbor_api_token})
    json_response = response.json()
    source_ips = json_response['data']['attributes']['source_ips']
    return source_ips


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
                         help="specify the address to bind the monitor to for Arbor webook notifications"
                              "(or set DIS_ARBORMON_BIND_ADDRESS)")
arg_parser.add_argument ('--bind-port', "-p", required=False, action='store', type=int,
                         default = os.environ.get('DIS_ARBORMON_BIND_PORT', 443),
                         help="specify the port to bind the HTTP/HTTPS server to "
                              "(or set DIS_ARBORMON_BIND_PORT)")
arg_parser.add_argument ('--cert-chain-file', "-ccf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBORMON_CERT_FILE'),
                         help="the file path containing the certificate chain to use for HTTPS connections "
                              "(or set DIS_ARBORMON_CERT_FILE)")
arg_default = os.environ.get('DIS_ARBORMON_KEY_FILE')
arg_parser.add_argument ('--cert-key-file', "-ckf", required=not arg_default,
                         action='store', type=open, default=arg_default,
                         help="the file path containing the key for the associated certificate file " 
                              "(or DIS_ARBORMON_KEY_FILE)")
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
    logger.info("RUNNING IN DRY-RUN MODE")
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


app.run(debug=args.debug, host=args.bind_address, port=args.bind_port,
        certfile=cert_chain_filename, keyfile=cert_key_filename)
