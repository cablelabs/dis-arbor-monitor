from quart import Quart,request
import json, requests, logging
from attack import Attack

import client_config as cfg

logging_filename=None
logging_filemode=None
logging.basicConfig (level=logging.DEBUG, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger ('dis-arbor-monitor')

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

app = Quart(__name__)


@app.route('/',methods=['POST'])

async def index():
    """
    This awaits data from Arbor and then parseses it into an attack object.
    Once an attack has been finished ie ongoing is False, then the code goes back out and queries for
    Source IPs and adds that to the attack object.

    """
    data = await request.data
    payload = json.loads(data)
    payload_data = payload["data"]
    attack_attributes = payload_data["attributes"]
    attack_id = payload_data.get("id")
    logger.debug("PAYLOAD:" + json.dumps(payload, indent=3))

    #check if ongoing
    if attack_attributes["ongoing"]:
        logger.info(f"Received notification of ONGOING attack (ID: {attack_id})")
    else:
        logger.info(f"Received notification of COMPLETED attack (ID: {attack_id})")
        attack = Attack(attack_id)
        attack.start_time = attack_attributes["start_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack_subobjects = attack_attributes["subobject"]
        attack.peak_pps = attack_subobjects["impact_pps"]
        attack.peak_bps = attack_subobjects["impact_bps"]
        attack.misuse_types = attack_subobjects["misuse_types"]
        attack.source_ips = get_source_ips(attack_id=attack.id)
        if len(attack.source_ips):
            send_event(attack)
        else:
            logger.warning(f"No source IPs found for attack {attack_id}")

    return 'hello'

def send_event(attack):
    """
    Sends event to Crits Server.

    Parameters:
    attack object

    Returns:
    crits request response.

    """
    post_url = f"{cfg.crits_api_url}:{cfg.crits_api_port}{cfg.crits_api_path}{cfg.crits_api_user}&api_key={cfg.crits_api_token}"
    logger.debug("POSTing to: " + post_url)
    event = json.loads(attack.output())
    r = requests.post(url=post_url,json=event,headers={"Content-Type": "application/json"})
    logger.debug("POST response: " + r.text)

def get_source_ips(attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id 

    Returns:

    Array of source IPs

    """

    response = requests.get(f"{cfg.arbor_api_prefix}/api/sp/v6/alerts/{attack_id}/source_ip_addresses",
                            verify=False,headers={"X-Arbux-APIToken":cfg.arbor_token})
    json_response = response.json()
    source_ips = json_response['data']['attributes']['source_ips']
    logger.debug(f"Found Source IPs for attack ID {attack_id}: {source_ips}")
    return source_ips


app.run(debug=True,host=cfg.https_bind_address,port=cfg.https_bind_port,
        certfile=cfg.https_tls_certfile,keyfile=cfg.https_tls_keyfile)




