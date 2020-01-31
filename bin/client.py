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
    data = await request.data
    #decode byte array
    f = open("attack_payload","ab")
    f.write(data)
    f.close()
    data_string = data.decode("utf-8")
    payload = json.loads(data_string)
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
        start_time = attack_attributes["start_time"]
        #format time for crits
        if ":" == start_time[-3:-2]:
            start_time = start_time[:-3]+start_time[-2:]
        attack.start_time = start_time
        stop_time = attack_attributes["stop_time"]
        if ":" == stop_time[-3:-2]:
            stop_time = stop_time[:-3]+stop_time[-2:]
        attack.stop_time = attack_attributes["stop_time"]
        attack_subobjects = attack_attributes["subobject"]
        attack.peak_pps = attack_subobjects["impact_pps"]
        attack.peak_bps = attack_subobjects["impact_bps"]
        attack.misuse_types = attack_subobjects["misuse_types"]
        attack.source_ips = get_source_ips(attack_id=attack.id)
        print("Attack ID:{} \n Finished".format(attack_id))
        print("JSON:{}".format(attack.output()))

    return 'hello'

def send_event(attack):
    post_url = "{}:{}{}{}&api_key={}".format(cfg.crits_api_url,cfg.crits_api_port,cfg.crits_api_path,cfg.crits_api_user,cfg.crits_api_token)
    print(post_url)
    formatted_url=urllib.parse.quote(post_url)
    r = requests.post(url=post_url,json=event)
    print (r.content) 

def get_source_ips(attack_id,impact_pps=None,impact_bps=None):
    response = requests.get("https://lab-arbos01.cablelabs.com/api/sp/v6/alerts/{}/source_ip_addresses".format(attack_id),
            verify=False,headers={"X-Arbux-APIToken":cfg.arbor_token}) 
    json_response = response.json()
    source_ips = json_response['data']['attributes']['source_ips']
    print ("Source IPS:{}".format(source_ips))
    return source_ips


app.run(debug=True,host='0.0.0.0',port=443,certfile='/etc/crits-client/combined.cer',keyfile='/etc/crits-client/private.key')




