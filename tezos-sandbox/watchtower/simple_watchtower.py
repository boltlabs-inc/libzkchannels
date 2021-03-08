from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from threading import Thread, Lock
from time import sleep
import requests
import argparse
import json

from jsonrpc import JSONRPCResponseManager, dispatcher


notification_dict = {}
ntf_service = None
verbose = 0
counter = 1
lock = None



def contract_all_update_search(contract_hash, start=None, end=None):
    global counter
    global notification_dict
    global lock

    # Variable where to store contract storage
    storage = None

    # Variable where to store RPC response
    response = ""

    # Notification request status for which we need to continue scanning
    status = ["in progress"]
    if not notification_dict[contract_hash]["bound_search"]:
        status.append("past scanned - in progress")

    # Which entrypoint we need to notify the contractor
    # This could actually be set by the contractor, and his identity would be irrelevant
    entrypoint = "custClose"
    if notification_dict[contract_hash]["user_id"] == "customer":
        entrypoint = "merchClose"

    try:
        # Format RPC request payload
        payload = {}
        payload["method"] = "contract_update"
        payload["jsonrpc"] = "2.0"
        payload["id"] = counter
        payload["params"] = {"contract_hash":contract_hash}
        if start is not None:
            payload["params"]["start"] = start
        if end is not None:
            payload["params"]["end"] = end

        # Update counter for new requests
        counter += 1

        # Send RPC request and receive response
        response = requests.post(ntf_service, json=payload)
        response = response.json()

        # Extract response result
        storage = json.loads(response["result"])
        if verbose:
            print(contract_hash)
            print(storage)
            print()

        # While the notification request exists and the notification service is still scanning 
        while contract_hash in notification_dict.keys() and storage["status"] in status:
            try:
                # Get response and extract storage
                response = requests.post(ntf_service, json=payload)
                response = response.json()

                storage = json.loads(response["result"])
                if verbose:
                    print(contract_hash)
                    print(storage)
                    print()

                # Get notification, if entrypoint of interest was called, break loop
                notifications = storage["data"]
                for key in notifications.keys():
                    if notifications[key]["entrypoint"] == entrypoint:
                        with lock:
                            del notification_dict[contract_hash]

            except Exception as e:
                print("Error", e)

            # Delay to avoid spamming the notification service
            sleep(2)

        # Send notificication to contractor
        # TODO update to send this to communication channel specified by contractor
        print("-------------- Sending response --------------")
        print(storage)
        print("----------------------------------------------")
        print()

        # Delete notification request
        if contract_hash in notification_dict.keys():
            with lock:
                del notification_dict[contract_hash]

    except Exception as e:
        print("Error", e)

def get_storage(contract_hash):
    storage = None
    response = ""
    try:
        # Format RPC request payload
        payload = {}
        payload["method"] = "get_storage"
        payload["jsonrpc"] = "2.0"
        payload["id"] = 0
        payload["params"] = {"contract_hash":contract_hash}

        # Send RPC request, receive response
        response = requests.post(ntf_service, json=payload)
        response = response.json()

        # Extract and return result
        storage = json.loads(response["result"])
        return storage
    except Exception as e:
        print("Error", response, e)
        return None

def clean_notifications():
    global notification_dict
    global lock

    # Check all notification request and delete sent ones
    with lock:
        notifications = list(notification_dict.keys())
        for ntf in notifications:
            if notification_dict[ntf]["status"] == "sent":
                del notification_dict[ntf]

@dispatcher.add_method
def list_requests():
    global lock

    # Send all notification request hashes as string
    ntf_list = ""
    try:
        with lock:
            for ntf in notification_dict.keys():
                ntf_list += ntf + " "
        return {"success": ntf_list}
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def get_request(contract_hash):
    global notification_dict
    global lock

    # Send notification request
    response = {}
    try:
        if contract_hash in notification_dict.keys():
            with lock:
                response = notification_dict[contract_hash]
        else:
            response = {"error": "Notification request not found."}
        return response
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def clear_request(contract_hash):
    global notification_dict
    global lock

    try:
        # Delete notification request if present
        if contract_hash in notification_dict.keys():
            with lock:
                del notification_dict[contract_hash]
            return {"success":"Notification request "+ str(contract_hash) + " successfully deleted."}
        else:
            return {"success":"Notification request "+ str(contract_hash) + " not found."}
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def clear_all():
    global lock

    try:
        # Clear all notification requests
        with lock:
            notification_dict.clear()
        return {"success": "All requests were successfully deleted."}
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def contract_update(contract_hash, user_id, start=None, end=None):
    global contract_dict
    global lock

    response = ""
    try:
        # If notification request already present, send it to contractor and set request to "sent"
        # TODO: a contract atm can only have one requests, we can change that by using the RPC ids instead
        if contract_hash in notification_dict:
            response = json.dumps(notification_dict[contract_hash])
            with lock:
                if notification_dict[contract_hash]["status"] == "finished":
                    notification_dict[contract_hash]["status"] = "sent"
            return response
        else:
            # Check contract exists
            contract_storage = get_storage(contract_hash)
            if contract_storage is None:
                return {"error" : "Contract "+ contract_hash +" does not exist."}

            # Check user identity
            if user_id not in ["customer", "merchant"]:
                return {"error": "Expected 'customer' or 'merchant' as identity, received: "+user_id+"."}

            bound_search = 0
            if end is not None:
                bound_search = 1

            # Make new notification request to notification service
            with lock:
                notification_dict[contract_hash] = {"contract_hash": contract_hash, "status":"in progress", "user_id":user_id, "bound_search":bound_search}
                response = json.dumps(notification_dict[contract_hash])
            Thread(target=contract_all_update_search, args=(contract_hash,), kwargs={"start":start, "end":end}).start()

            # Forward notification service as token the request was accepted
            return response
    except Exception as e:
        print("Error", e)
        return {"error":str(e)}


@Request.application
def application(request):
    try:

        if verbose:
            print("---- New request:", request.data, "\n")

        # Handle request
        response = JSONRPCResponseManager.handle(request.data, dispatcher)

        if verbose:
            print("---- Response:", response.json, "\n")

        # Clean sent requests
        clean_notifications()

        return Response(response.json, mimetype='application/json')
    except Exception as e:
        print("Error", e)
        return Response({"error": str(e)}, mimetype='application/json')

def main():
    global ntf_service
    global verbose
    global lock

    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument("-net", "--network", type=str, help="the network, such as mainnet, or a RPC node uri", default=None)
    parser.add_argument("-v", "--verbose", help="print notification updates", action="store_true")
    args = parser.parse_args()

    # Set network and get head's level
    if args.network is None:
        return "Network needed"
    ntf_service = args.network

    if args.verbose:
        verbose = True

    lock = Lock()

    run_simple('localhost', 40000, application)

if __name__ == '__main__':
    main()