from quart import Quart,request
import json
import requests
import sys 
import jsonschema
from jsonschema import validate
from attack import Attack
from datetime import datetime

import client_config as cfg 

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

app = Quart(__name__)

@app.route('/',methods=['POST'])



async def index():
    """
    This awaits data from Arbor and then parseses it into an attack object.
    Once an attack has been finished ie ongong is False, then the code goes back out and queries for 
    Source IPs and adds that to the attack object.

    """
    data = await request.data
    payload = json.loads(data)
    payload_data = payload["data"]
    attack_attributes = payload_data["attributes"]
    print("PAYLOAD:{}".format(payload))

    #check if ongoing
    if attack_attributes["ongoing"]:
        try:
            print("New/Ongoing Attack ID :{} \n Ongoing waiting".format(payload_data['id']))
        except:
            print(payload_data)
    else:
        attack_id = payload_data["id"]
        attack = Attack(attack_id)
        attack.start_time = attack_attributes["start_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack_subobjects = attack_attributes["subobject"]
        attack.peak_pps = attack_subobjects["impact_pps"]
        attack.peak_bps = attack_subobjects["impact_bps"]
        attack.misuse_types = attack_subobjects["misuse_types"]
        attack.source_ips = get_source_ips(attack_id=attack.id)
        print("Attack ID:{} \n Finished".format(attack_id))
        print("JSON:{}".format(attack.output()))
        if len(attack.source_ips):
            send_event(attack)
        else:
            print("Empty Event")

    return 'hello'

def send_event(attack):
    """
    Sends event to Crits Server.

    Parameters:
    attack object

    Returns:
    crits request response.

    """
    post_url = "{}:{}{}{}&api_key={}".format(cfg.crits_api_url,cfg.crits_api_port,cfg.crits_api_path,cfg.crits_api_user,cfg.crits_api_token)
    print(post_url)
    event = json.loads(attack.output())
    r = requests.post(url=post_url,json=event,headers={"Content-Type": "application/json"})
    print (r.content) 

def get_source_ips(attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id 

    Returns:

    Array of source IPs

    """
    response = requests.get("https://lab-arbos01.cablelabs.com/api/sp/v6/alerts/{}/source_ip_addresses".format(attack_id),
            verify=False,headers={"X-Arbux-APIToken":cfg.arbor_token}) 
    json_response = response.json()
    source_ips = json_response['data']['attributes']['source_ips']
    print ("Source IPS:{}".format(source_ips))
    return source_ips


app.run(debug=True,host='0.0.0.0',port=443,certfile='/etc/crits-client/combined.cer',keyfile='/etc/crits-client/private.key')




