# Installation Guide for the DDoS Info Sharing (DIS) Netscout Arbor Sightline Monitor/Client

### v 0.4

## 1. Introduction

The Arbor Sightline Monitor/Client interfaces with an Arbor/NetScout Sightline
9.x system to receive notifications from the system when DDoS attacks are
detected and upload the relevant metadata (most specifically the source IP
addresses) into the DIS server database. From the DIS database, owners of the
source IP address can determine if and how devices on their networks are
contributing to DDoS attacks.

This guide details how to setup the CableLabs DDoS Information Sharing (DIS)
Monitor/Client for Sightline 9.x systems.

## 2. Create an API key for the Monitor/Client

Using the provided credentials, go to <https://dissarm.net/clients> and select
“Provision New Client.”

NOTE: If you don’t already have credentials for the DIS management system,
CableLabs will create one or more logins for your organization and provide
initial credentials.

>   ![](media/0409d925191e43de79b16d1269663a69.png)

>   ![](media/3d32707632e74562a787e663124a643a.png)

>   ![](media/3eb7b1a158c2a2e95226a7022edea5f5.png)

Once completed, make note of the “API Key” to use below.

Note: Disregard the “Installation” instructions provided in the UI for the
time-being. These will be updated to reflect these installation instructions in
a future update of the DIS backend.

## 3. Create a sightline API key

If you don’t already have an API key setup, generating an Arbor API key requires
access to the Arbor Sightline CLI. This is described in the “Enabling Customers
to View Sightline Data in the Web Services API” section of the *Sightline and
Threat Mitigation System User Guide*.

From the Netscout CLI, enter the following command:

`/ services aaa local apitoken generate user_name "token_description"`

If an API token exists (or if you’re not sure one exists), use:

`/ services aaa local apitoken show`

To show any active API tokens. Make note of the Arbor REST API token for the
steps below.

## 4. Install the DDoS Info Sharing (DIS) Monitor/Client (v2)

The DIS Arbor Monitor/Client requires the following:

-   An Arbor/Netscout Sightline 9.x (Peakflow SP 9.1+) server with:

    -   Accessibility from the server hosting the DIS Arbor Monitor on port 443

    -   Optionally, a https server certificate that the DIS Client can use to
        validate the server (when configuring the client to access the SP API
        using https)

    -   Optionally, a root certificate that allows for validation of SP webhook
        calls (when configuring SP with https-based webhooks)

-   A server to host the Monitor/Client with:

    -   Python 3.6 (or higher) or the Docker container management system

    -   Support for incoming TCP connections established from Arbor Netscout
        (http or https)

    -   Access to the Arbor Netscout REST API (e.g.
        http://arbor-hostname-or-ip/)

    -   A network connection allowing outbound HTTPS connections (specifically
        to <https://dissarm.net/>)

    -   Optionally, a https server certificate that the Sightline 9.x system can
        use to validate the server (when configuring Sightline webhooks using
        https)

    -   Optionally, a root certificate that allows for validation of Sightline
        API REST calls (when configuring the DIS Client with an https URI)

For installing the DIS Arbor Monitor/Client, perform the following:

1.  Retrieve the latest Docker management script for the DDOS Info Sharing
    client:

-   `wget
    https://raw.githubusercontent.com/cablelabs/dis-arbor-monitor/master/arbormon-container.sh`

-   `wget
    https://raw.githubusercontent.com/cablelabs/dis-arbor-monitor/master/arbormon-container.conf`

1.  Install the script:

    -   `sudo mkdir /etc/dis-arbor-monitor/`

    -   `sudo install -v -o root -m 755 -D -t /etc/dis-arbor-monitor/
        arbormon-container.sh`

    -   `sudo install -v -o root -m 600 -D -C -t /etc/dis-arbor-monitor/
        arbormon-container.conf`

2.  Configure the settings for your environment:

    -   `sudo vim /etc/dis-arbor-monitor/arbormon-container.conf`

        Which should contain settings for the following variables:

-   DOCKER_CMD to the command to execute to invoke Docker (just “docker” if the
    user is already in the “docker” group or “sudo docker” if the user is not)

-   DEF_IMAGE_LOCATION/TAG to whatever values are provided by the DIS project
    integrator

-   DEF_CONTAINER_NAME should be set to “dis-arbor-monitor-service”

-   DEF_DEBUG can be set to “True” to enable debug logging. The default is for
    debug logging to be disabled.

-   DEF_TLS_CERT_CHAIN_FILE/KEY_FILE should be set to the paths containing the
    TLS/HTTPS certificate and private key for the server running the monitor.
    These should only be set if (a) the Arbor web hook is setup with an https
    URI, and (b) when a HTTPS web proxy isn’t being used to handle the HTTPS
    connection (e.g. nginx)

-   DEF_BIND_PORT/ADDRESS need to be set in accordance with how the Arbor
    webhook is setup. If the webhook is “http” (with the default port) than
    these should be either “0.0.0.0” and “80” or to be more explicit, the IP
    address of the Arbor-accessible interface and “80”. If a https proxy is
    used, these should be set to “127.0.0.1” and some arbitrary port, such as
    “8080”.

-   DEF_ARBOR_REST_API_PREFIX should be set to the http or https URI prefix for
    the Arbor NetScout REST API. Usually this will just be set to a URI of the
    form “<https://arbor-netscout-hostname.acme.com/>”

-   DEF_ARBOR_REST_API_TOKEN should be set to the key setup in the previous
    section (see section ”Create a sightline API key”)

-   DEF_REPORT_CONSUMER_API_KEY is set to the API key created in the previous
    section (see section “Create an API key for the Monitor/Client”)

-   DEF_REPORT_CONSUMER_HTTP_PROXY can be set to the URI of an HTTP/HTTPS proxy.
    (e.g. “http://10.0.1.11:1234” or “https://proxy.acme.com:8080”)

-   DIS_ARBORMON_WEBHOOK_TOKEN can be set to a random string which is provided
    in the webhook URI as a way to authenticate the webhook invocation. e.g.
    “openssl rand -hex 10”

-   DEF_MAX_QUEUED_REPORTS is set to the number of attack reports that the
    client will queue if/when communication is lost with the DIS backend server.
    If unset, the client will queue indefinitely.

-   DEF_SYSLOG_SERVER can be set to the hostname/address of a syslog server
    listening for syslog events on UDP port 514 (e.g. “logserve.acme.com”) or to
    the port designated after a “:” (e.g. “logserve.acme.com:5514”). Any
    INFO-level logging (or higher) will be sent to the designated SYSLOG server
    via UDP (in addition to any other syslog destinations set).

-   DEF_SYSLOG_TCP_SERVER can be set to the hostname/address of a syslog server
    listening for syslog events on TCP port 601 (e.g. “logserve.acme.com”) or to
    the port designated after a “:” (e.g. “logserve.acme.com:5601”). Any
    INFO-level logging (or higher) will be sent to the designated SYSLOG server
    via TCP (in addition to any other syslog destinations set).

-   DEF_SYSLOG_SOCKET can be set to the filename of a syslog socket file. Any
    INFO-level logging (or higher) will be sent to the designated SYSLOG socket
    (in addition to any other syslog destinations set).

-   DEF_SYSLOG_FACILITY can be set to the desired syslog facility code (an
    integer). If unset any syslog logging will be logged to facility LOG_USER.

-   DEF_LOG_PREFIX can be set to an arbitrary string that will prefix all
    logging messages from the client – both within the docker container and
    messages logged via syslog

-   DEF_LOG_REPORT_STATS can be set to a positive integer representing the
    frequency (in minutes) where the client will periodically perform INFO-level
    logging reporting the number of attack events and source IP addresses
    reported during the last time period. e.g.

-   DEF_REPORT_STORE_DIR can be set to a directory where a local report file
    will be written each time an attack is processed, for local processing. If
    unset, report files are not generated by the client.

-   DEF_REPORT_STORE_FORMAT can be set to either "only-source-attributes" or
    "all-attributes". If not set, the default is "only-source-attributes"

The “only-source-attributes” format includes only information related to the
attack source – omitting data such as the target IP, source router, and other
information not related to the attack source. Here’s an example of the
“only-source-attributes” format:

The “all-attributes” format includes additional attributes not related to the
attack source – attributes which are not reported to the DIS backend but which
may be of interest/use of local facilities. For example the attack target and
relevant router names will be included in the report. Here’s an example of the
“all-attributes” format

Here’s an example of the */etc/dis-arbor-monitor/arbormon-container.conf* file:

NOTE: This conf file should have permissions set to prevent it from being
world-readable if the system is multi-user (e.g. “chmod o-rw
/etc/dis-arbor-monitor/arbormon-container.conf”). This will require the user
executing the script to have permissions set to allow access to the file or to
use “sudo” to execute the script.

1.  Download the Docker image:

2.  /etc/dis-arbor-monitor/arbormon-container.sh docker-pull

3.  Start the DIS Arbor Monitor Docker container:

4.  /etc/dis-arbor-monitor/arbormon-container.sh docker-run

5.  Check for successful startup:

6.  /etc/dis-arbor-monitor/arbormon-container.sh docker-logs

7.  On successful startup, the logs should start with something similar to:

## Configure Arbor Netscout to notify the Monitor/Client

To configure Arbor NetScout to notify the DIS monitor/client, perform the
following:

1.  Setup a Managed Object with suitable DDoS notification limits:

2.  ![](media/309b011e5fea0ebae6b8165bae4f5d72.tiff)

3.  ![](media/1a011c0556d8f8f46735b6f646aee4de.tiff)

4.  ![](media/86ca4698333e07c8832f8bc437d9f6b7.tiff)

5.  ![](media/66d42ad015fca9c84161bfe3b6e26142.tiff)

6.  ![](media/6103279cc0fadee8c3cd20d447cd3aaa.tiff)

7.  Create a notification group:

8.  ![](media/c1584edaade639f0bc6c291018be7545.tiff)

9.  ![](media/466c16d73b2e9bb1e20bd3568774be37.tiff)

10. ![](media/e29988df9d2eeb64a151332a28689f8b.tiff)

11. Webhook “URI” provided here is just an example. This field must be
    coordinated with the configuration of the DIS Monitor/Client as described in
    Section 4 (Install the DDoS Info Sharing (DIS) Monitor/Client (v2)).

12. If the DIS client is setup to listen for http notifications (with no TLS
    cert configured), then an URI of the form “http://fqdn-or-ip/dis/sl-webhook”
    will be an appropriate Webhook URI. If https is desired, then the form must
    be “https://fqdn-or-ip/dis/sl-webhook” where the host/service handling the
    webhook call has a TLS cert registered for the fqdn and signed by a CA
    trusted by the Arbor Netscout server (the service’s cert is signed directly
    or indirectly by a CA trusted by the server). Note than in either case the
    default http/https port can be over-ridden by appending “:portnum” to the
    webhook URI.

13. In addition to configuring the protocol and URI path, the DIS client can be
    configured to authenticate webhook invocations via a “token” parameter. For
    example a webhook URI of the form:

14. https://fqdn-or-ip/dis/sl-webhook?token=03240717821fe3531b13

15. Would be required to invoke the DIS client webhook if it’s configured to
    only allow webhook invocations with the provided token. Note that this form
    is only reliable when used with https – since the URI (including the token)
    will not be encrypted on http connections.

16. Setup a notification rule for the Managed Object setup above to utilize the
    Notification Group containing the webhook:

17. ![](media/66d8e7812d8e694409ccf5b52d9bca86.tiff)

18. Commit the config once the changes are complete:

19. ![](media/88cd7d2d833552870570e1ae393bc03a.tiff)

20. ![](media/219310eb1cbfe6e75496d27aa12bf231.tiff)

21. Configure webhook notification limits to prevent excessive queuing of
    webhook notifications.

22. Arbor Sightline will only consider a webhook “invoked” if it’s able to POST
    the webhook notification body to the configured webhook endpoint URI(s) and
    the endpoint returns a HTTP 200 (success) status code. If the webhook isn’t
    successfully invoked, Sightline will attempt to invoke the endpoint again,
    after a period, and will continue to do so until the endpoint is
    successfully invoked.

23. If there’s a concern that Sightline won’t be able to connect to the DIS
    client due to network connectivity issues or regular maintenance, you may
    want to configure Sightline to limit its retry behavior – since it can
    impact the memory usage and performance of the system.

24. The following options can be set to control the notification behavior via
    the Arbor Sightline API:

-   The “notification webhooks retry_count_limit” and “notification webhooks
    retry_count_max set” variables will limit the number of times a webhook will
    be invoked for a particular attack report

-   The “notification webhooks retry_seconds_limit” and “notification webhooks
    retry_seconds_max” will control the retry frequency for webhook
    notifications for a particular attack report

1.  For example, to set the webhook notification to perform no more than 10
    notifications per attack – with 1 minute between notifications, the
    following commands can be invoked on the Sightline CLI:

## Validation

Confirmation of the invocation of the configured webhook can be performed by
examining the DIS Arbor Monitor/Client log. The log can be retrieved by running
the following command:

>   /etc/dis-arbor-monitor/arbormon-container.sh docker-logs

When an attack is detected, the first indication you will see in the DIS Arbor
monitor/client log will be an entry of the form:

Then once the attack is completed – and the attack metadata and source IP
addresses have been determined – you should see log entries of the form:

If Arbor Netscout indicates that a DDoS attack was detected, and there’s no
corresponding log entry, then check the configuration. Or to verify the webhook
address is correct, you can use curl to perform a GET on the webhook URI and
verify the monitor/client can be contacted. For example:

>   curl http://arbormon-001.acme.com

or if custom certs are being used with https on a custom port:

>   curl --insecure https://arbormon-001.acme.com:8443

If the URI is correct, the DIS Arbor Monitor log should print an entry when it
rejects the GET request:

If not, check the monitor configuration values and if using https with a custom
CA certs, use the curl “—cacert” to ensure the CA cert is valid and matches the
one running on the monitor server. If it does validate, ensure the CA cert is
added to the Arbor Monitor trust store.
