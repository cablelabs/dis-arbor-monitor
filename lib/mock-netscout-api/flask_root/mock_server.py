from flask import Flask, send_from_directory,request
from flask_json import FlaskJSON
from pathlib import Path
from flask_api import status



app = Flask(__name__)
json = FlaskJSON(app)

# Get the parent directory of this script. (Global)
parent_path = Path(__file__).parent

#set the path to the alers dir  
alert_storage_path = Path(parent_path).joinpath('../server-root/api/sp/v6/alerts/')
webhook_storage_path =  Path(parent_path).joinpath('../webhook-files/')
sp_path = Path(parent_path).joinpath('../server-root/api/') 



@app.route("/api/sp", methods= ['GET'])
def get_api():
    """Serve the sp.json file"""
    try:
        return send_from_directory(sp_path,'sp.json') 
    except:
        return "Record not found", status.HTTP_400_BAD_REQUEST

#Get list of root Alert Files as links to source_ip_address
def get_files_from_this_directory():
    """Create a generator that yields the items within this script's directory."""
    for item in alert_storage_path.iterdir():
        if not item.name.startswith("."):
            yield item.name

@app.route("/files/<alert_id>",methods= ['GET'])
def serve_alert_file(alert_id):
    """Set up a dynamic routes for directory items at /files/"""
    try:
        return send_from_directory(alert_storage_path, alert_id+"/source_ip_addresses.json")
    except:
        return "Record not found", status.HTTP_400_BAD_REQUEST

@app.route("/files/<alert_id>/traffic/<prefix_file>",methods= ['GET'])
def serve_traffic_file(alert_id,prefix_file):
    """Set up a dynamic routes for directory items at /files/"""
    try:
        return send_from_directory(alert_storage_path.joinpath(alert_id+"/traffic/"),prefix_file)
    except:
        return "Record not found", status.HTTP_400_BAD_REQUEST


@app.route("/dis/sl-webhook", methods=['POST'])
def serve_webhook():
    """Serve up webhook
    Example: curl -vv -X POST http://localhost:5000/dis/sl-webhook --data Attack-5790226-WebHook.json"""
    try:
        file = request.get_data().decode("utf-8")+"k"
        return send_from_directory(webhook_storage_path,file)
    except:
        return "Record not found", status.HTTP_400_BAD_REQUEST
        

def html_ul_of_items():
    """Create a unordered list of anchors/links to file routes."""
    html = "<ul>"
    for item in get_files_from_this_directory():
        html += f"<li><a href='files/{item}'>{item}</a`></li>"
    return html + "</ul>"

@app.route("/")
def list_files():
    """Root route which displays an unordered list of directory items."""
    print(alert_storage_path)
    return html_ul_of_items()


if __name__ == '__main__':
    app.run()
