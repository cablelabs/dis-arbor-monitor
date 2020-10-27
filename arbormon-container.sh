#!/bin/bash

set -e

# Uncomment this on to debug the script
# set -x

shortname="${0##*/}"
longname="DIS arbor monitor"
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
conf_file=$script_dir/$(basename $shortname .sh).conf

if [ -e $conf_file ]; then
    echo "Reading from conf file: $conf_file"
    source $conf_file
fi

function abs_path_for_file()
{
    if [ $# -gt 0 ]; then
        filepath=$*
        abs_file=$( cd "${filepath%/*}" && pwd )"/"${filepath##*/}
        echo "$abs_file"
    fi
}

function bailout()
{
    local message="$1"
    echo "$shortname: error: ${message}" >&2
    exit 1;
}

function bailout_with_usage()
{
    local message="$1"
    echo "$shortname: error: ${message}" >&2
    print_usage
    exit 1;
}

function print_usage()
{
    echo " "
    echo "Usage: ${shortname} <operation>"
    echo ""
    echo "   operation can be one of:"
    echo ""
    echo "     docker-pull: Download the $shortname docker image"
    echo "     docker-run: Create and start the $shortname docker container"
    echo "     docker-run-interactive: Start a shell to run $shortname (for debugging)"
    echo "     docker-status: Show the status of the $shortname docker container"
    echo "     docker-kill: Kill the $shortname docker container"
    echo "     docker-rm: Delete the $shortname docker container (can recreate with docker-run)"
    echo "     docker-restart: Restart the $shortname docker container"
    echo "     docker-logs: Show the logs for $shortname docker container"
    echo "     docker-trace: Watch the logs for the $shortname docker container"
    echo "     docker-address: Print the IP addresses for the $shortname docker container"
    echo "     docker-env: List the environment variables for the $shortname docker container"
    echo "     docker-shell: Start an interactive shell into the running docker service container"
    echo ""
    echo "   [--docker-image <docker image ID>]"
    echo "       (default \"$DEF_IMAGE_LOCATION\")"
    echo "   [--docker-image-tag <docker image tag>]"
    echo "       (default \"$DEF_IMAGE_TAG\")"
    echo "   [--docker-name <docker name to assign>]"
    echo "       (default \"$DEF_CONTAINER_NAME\")"
    echo "   [--bind-address <address to bind ${shortname} to>]"
    echo "       (default \"$DEF_BIND_ADDRESS\")"
    echo "   [--bind-port <port to bind ${shortname} to>]"
    echo "       (default \"$DEF_BIND_PORT\")"
    echo "   [--tls-cert-chain-file <certificate chain file for HTTPS connections>]"
    echo "       (default \"$DEF_TLS_CERT_CHAIN_FILE\")"
    echo "   [--tls-priv-key <private key for for HTTPS connections>]"
    echo "       (default \"$DEF_TLS_PRIV_KEY_FILE\")"
    echo "   [--arbor-api-prefix <url prefix for the arbor rest api>]"
    echo "       (default \"$DEF_ARBOR_REST_API_PREFIX\")"
    echo "   [--arbor-api-token <the arbor api token>"
    echo "       (default \"$DEF_ARBOR_REST_API_TOKEN\")"
    echo "   [--report-consumer-url <url for posting report data>]"
    echo "       (default \"$DEF_REPORT_CONSUMER_URL\")"
    echo "   [--report-consumer-api-key <API key for reporting>]"
    echo "       (default \"$DEF_REPORT_API_KEY\")"
}

function process_arguments()
{
    shopt -s nullglob
    shopt -s shift_verbose

    operation=""
    docker_image_id="$DEF_IMAGE_LOCATION"
    docker_image_tag="$DEF_IMAGE_TAG"
    container_name="$DEF_CONTAINER_NAME"
    tls_cert_chain_file=$(abs_path_for_file "$DEF_TLS_CERT_CHAIN_FILE")
    tls_priv_key_file=$(abs_path_for_file "$DEF_TLS_PRIV_KEY_FILE")
    bind_address="$DEF_BIND_ADDRESS"
    bind_port="$DEF_BIND_PORT"
    arbor_rest_api_prefix="$DEF_ARBOR_REST_API_PREFIX"
    arbor_rest_api_token="$DEF_ARBOR_REST_API_TOKEN"
    report_consumer_url="$DEF_REPORT_CONSUMER_URL"
    report_consumer_api_key="$DEF_REPORT_CONSUMER_API_KEY"
    debug=

    while [[ $1 == --* ]]; do
        opt_name=$1
        if [ "$opt_name" == "--docker-image" ]; then
            shift
            docker_image_id="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--docker-image-tag" ]; then
            shift
            docker_image_tag="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--docker-name" ]; then
            shift
            container_name="$opt_name"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--tls-cert-chain-file" ]; then
            shift
            tls_cert_chain_file=$(abs_path_for_file $1)
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--tls-priv-key" ]; then
            shift
            tls_priv_key_file=$(abs_path_for_file $1)
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--bind-address" ]; then
            shift
            bind_address="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--bind-port" ]; then
            shift
            bind_port="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--arbor-api-prefix" ]; then
            shift
            arbor_rest_api_prefix="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--arbor-api-token" ]; then
            shift
            arbor_rest_api_token="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--report-consumer-url" ]; then
            shift
            report_consumer_url="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--report-consumer-api-key" ]; then
            shift
            report_consumer_api_key="$1"
            shift || bailout_with_usage "missing parameter to $opt_name"
        elif [ "$opt_name" == "--debug" ]; then
            shift
            debug=true
        else
            bailout_with_usage "Unrecognized option: $opt_name"
        fi
    done

    if [ $# -lt 1 ]; then
        bailout_with_usage "Missing operation"
    fi

    operation=$1
    shift

    if [ ! -z $debug ]; then
        echo "docker_image_id: $docker_image_id"
        echo "docker_image_tag: $docker_image_tag"
        echo "container_name: $container_name"
        echo "tls_cert_chain_file: $tls_cert_chain_file"
        echo "tls_priv_key_file: $tls_priv_key_file"
        echo "bind_address: $bind_address"
        echo "bind_port: $bind_port"
        echo "arbor_rest_api_prefix: $arbor_rest_api_prefix"
        echo "arbor_rest_api_token: $arbor_rest_api_token"
        echo "report_consumer_url: $report_consumer_url"
        echo "report_consumer_api_key: $report_consumer_api_key"
    fi
}

function docker-pull()
{
    echo "Pulling docker image from $docker_image_id:$docker_image_tag"
	$DOCKER_CMD pull $docker_image_id:$docker_image_tag
}

function docker-run()
{
    if [ -z "$arbor_rest_api_prefix" ]; then
        bailout "Arbor rest API URL not specified (use --arbor-api-prefix to specify)"
    fi

    if [ -z "$arbor_rest_api_token" ]; then
        bailout "Arbor rest API token not specified (use --arbor-api-token to specify)"
    fi

    if [ ! -z "$tls_cert_chain_file" -a ! -z "$tls_priv_key_file" ]; then
        cert_key_mount_args=(--mount type=bind,source="$tls_cert_chain_file",target=/app/lib/tls-cert-chain.pem,readonly
                             --mount type=bind,source="$tls_priv_key_file",target=/app/lib/tls-key.pem,readonly)
        cert_key_command_args=(--cert-chain-file /app/lib/tls-cert-chain.pem
                               --cert-key-file /app/lib/tls-key.pem)
    fi

    if [ ! -z "$debug" ]; then
        debug_opt="--debug"
    fi

    docker_run_params=(python3.6 /app/arbor-monitor
                              $debug_opt
                              --bind-port "$bind_port"
                              --arbor-api-prefix "$arbor_rest_api_prefix"
                              --arbor-api-token "$arbor_rest_api_token"
                              --report-consumer-url "$report_consumer_url"
                              --report-consumer-api-key "$report_consumer_api_key"
                              "${cert_key_command_args[@]}")
    exec_options=(--read-only -d --restart unless-stopped)

    if [ "$1" == "interactive" ]; then
        echo "Starting interactive shell."
        echo -n "Start the service manually using:"
        for arg in "${docker_run_params[@]}" ; do echo -n " \"$arg\""; done;
        echo ""
        docker_run_params=(/bin/bash)
        exec_options=(-it)
    else
        echo "Starting the $longname as a docker service."
        echo "The the $longname service will restart on error or on system restart."
        echo "Use '$shortname docker-kill' to terminate the service"
    fi

    echo "Starting container \"$container_name\" from $docker_image_id:$docker_image_tag (on $bind_address:$bind_port)"
    $DOCKER_CMD run "${exec_options[@]}" \
        --name "$container_name" \
        -p "$bind_address:$bind_port:$bind_port" \
        "${cert_key_mount_args[@]}" \
        "$docker_image_id:$docker_image_tag" \
        "${docker_run_params[@]}"
}

function docker-run-interactive()
{
    docker-run interactive
    sleep 1
    docker-rm
}

function docker-rm()
{
    echo "Attempting to remove container \"$container_name\""
    $DOCKER_CMD container rm $container_name
}

function docker-kill()
{
    echo "Attempting to kill and remove container \"$container_name\""
    $DOCKER_CMD container kill $container_name
    sleep 1
    docker-rm
}

function docker-restart()
{
    echo "Attempting to restart container \"$container_name\""
    $DOCKER_CMD container restart $container_name
}

function docker-update()
{
    echo "Attempting to update container image \"$container_name\""
    docker-kill
    docker-pull
    docker-run
}

function docker-logs()
{
    echo "Showing logs for container \"$container_name\""
    $DOCKER_CMD container logs --timestamps $container_name
}

function docker-trace()
{
    echo "Tracing logs for container \"$container_name\""
    $DOCKER_CMD container logs --timestamps --follow --tail 50 $container_name
}

function docker-bash()
{
    echo "Opening bash session for container \"$container_name\""
    docker exec -it $container_name /bin/bash
}

function docker-address()
{
    ip_address=$($DOCKER_CMD inspect \
                 -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
                 ${container_name})
    if [ -z "$ip_address" ]; then
        bailout "Could not get the IP address for container $container_id"
    fi
    echo "${ip_address}"
}

function docker-shell()
{
    echo "Starting interactive shell on container $container_name"
    docker exec -it $container_name /bin/bash
}

function docker-status()
{
    echo "ARBOR MONITOR CONTAINERS"
    echo "---------------------"
    $DOCKER_CMD container ps -a --filter name=$container_name
}


#
# main logic
#

process_arguments "$@"

$operation
