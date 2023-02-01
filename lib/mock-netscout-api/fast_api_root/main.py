from fastapi import FastAPI,HTTPException,UploadFile,File
from fastapi.responses import HTMLResponse,FileResponse,JSONResponse
from pathlib import Path
"""
The below can be used as context headers on each function.
To enable uncomment this section and uncomment the openapi_tags in the app = FastAPI
tags_metadata = [
    {
    "name":"alerts",
    "description":"Serve an Alert file based on alert ID.  Example:  curl"     
    },
    {
    "name":"api_info",
    "description":"Returns API info susch as version.  Example:  curl"
    }
]
"""

app = FastAPI(
    title="Mock Netscout Server",
    description="Used for testing the DIS Arbor Client",
    version="0.1",
    contact={
        "name":"Kyle Haefner",
        "email":"k.haefner@cablelabs.com"
    },
    #openapi_tags=tags_metadata
    )

"""Get the parent directory of this script. (Global)"""
parent_path = Path(__file__).parent

"""Set the path to the alerts dir """
alert_storage_path = Path(parent_path).joinpath('../server-root/api/sp/v6/alerts/')
webhook_storage_path =  Path(parent_path).joinpath('../webhook-files/')
sp_path = Path(parent_path).joinpath('../server-root/api/sp.json') 



"""Get list of root Alert Files as links to source_ip_address"""
def get_files_from_this_directory():
    """Create a generator that yields the items within this script's directory."""
    for item in alert_storage_path.iterdir():
        if not item.name.startswith("."):
            yield item.name

def html_ul_of_items():
    """Create a unordered list of anchors/links to file routes."""
    html = "<ul>"
    for item in get_files_from_this_directory():
        html += f"<li><a href='files/{item}'>{item}</a`></li>"
    return html + "</ul>"

#API info
@app.get("/api/sp",status_code=404,tags=["api_info"])
def get_api():
    """Return Information on the API.  """
    try:
        return FileResponse(sp_path,media_type="application/json")
    except:
        raise HTTPException(status_code=404, detail="Item not found")

#Serve Alert Files
@app.get("/files/{alert_id}",tags=["alerts"])
def serve_alert_file(alert_id:int):
    """Serve the ALert file:  Example:  curl """
    try:
        alert_file_path = alert_storage_path.joinpath(alert_id,"source_ip_addresses.json")
        return FileResponse(alert_file_path)
    except:
        raise HTTPException(status_code=404, detail="Item not found")

#Serve Prefix Files
@app.get("/files/{alert_id}/traffic/{prefix_file}",tags=['prefixes'])
def serve_traffic_file(alert_id,prefix_file):
    """Return prefixes associeted with alert"""
    try:
        prefixes = alert_storage_path.joinpath(alert_id+"/traffic/",prefix_file)
        return FileResponse(prefixes)
    except:
        raise HTTPException(status_code=404, detail="Item not found")

@app.post("/dis/sl-webhook",tags=['webhook'])
async def serve_webhook(file: UploadFile = File(...)):
    """Serve up webhook
    Example: curl -vv -X POST http://localhost:5000/dis/sl-webhook --data Attack-5790226-WebHook.json"""
    #try:
        #file = request.get_data().decode("utf-8")+"k"
        #return send_from_directory(webhook_storage_path,file)
    #webhook = webhook_storage_path.joinpath(file.filename)
    file_name = file.filename
    print(file_name)
    #except:
    #   raise HTTPException(status_code=404, detail="Item not found")

#Root Returns list of files in alerts dir 
@app.get("/",response_class=HTMLResponse,tags=['list_alerts'])
def list_files():
    """Return list of alert files"""
    print(alert_storage_path)
    return html_ul_of_items()

