from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from threading import Thread, Lock
from pytezos import pytezos
from time import sleep
import argparse
import json

from jsonrpc import JSONRPCResponseManager, dispatcher


contract_dict = {}
lock = None
run_head_level = -1
network = None
verbose = 0


def contract_origin_search(contract_hash):
    start = 0
    end = pytezos.using(shell=network).shell.head.header()["level"]
    contract = pytezos.using(shell=network).contract(contract_hash)
    found = -1
    storage = None
    while found == -1:
        anchor = int((end+start+1)/2)
        try:
            storage = contract.storage(anchor)
            try:
                storage = contract.storage(anchor-1)
                end = anchor
            except Exception:
                found = anchor
        except Exception :
            start = anchor
    if verbose:
        print_notification(found, contract_hash, entrypoint="contract creation", storage=storage)
    return make_notification(found, contract_hash, entrypoint="contract creation", storage=storage)


def contract_all_update_search(contract_hash, start=None, end=None):
    global contract_dict
    global lock

    p = pytezos.using(shell=network)

    # Get origin data and origin level
    contract = p.contract(contract_hash)
    creation_notification = contract_origin_search(contract_hash)

    # Store notification for future call
    data = contract_dict[contract_hash]["data"]
    data[creation_notification["level"]] = creation_notification

    with lock:
        contract_dict[contract_hash]["data"] = data


    # Start scanning from either start or origin level
    counter = start
    if start is None or creation_notification["level"] > start:
        counter = creation_notification["level"]

    # Scan
    while counter != end:

        # If contract_dict does not have contract_hash, stop scanning
        if contract_hash not in contract_dict.keys() or contract_dict[contract_hash] == "finished":
            break

        try:
            block = p.shell.blocks[counter]()
            operations = block["operations"][3]

            # For each operation in the block
            for op in operations:
                op_hash = op["hash"]
                contents = op["contents"]

                # For each content
                for content in contents:
                    if "destination" in content.keys() and "parameters" in content.keys():

                        # If the destination is a contract we were asked to scan
                        if content["destination"] == contract_hash:
                            entrypoint = content["parameters"]["entrypoint"]

                            # Get contract storage
                            storage = p.contract(contract_hash).storage(counter)

                            # Get notification request
                            data = contract_dict[contract_hash]["data"]
                            max_level_before_end = max([lvl for lvl in contract_dict[contract_hash]["data"].keys() if lvl < end])

                            if verbose:
                                print_notification(counter, contract_hash, entrypoint=storage["status"], storage=storage)

                            # Make notification, save contract storage if different from notification request
                            notification = make_notification(counter, contract_hash, entrypoint=entrypoint)
                            if storage != data[max_level_before_end]:
                                notification = make_notification(counter, contract_hash, entrypoint=entrypoint, storage=storage)

                            # Store notification for future call
                            data[counter] = notification
                            with lock:
                                contract_dict[contract_hash]["data"] = data


        except Exception as e:
            print("Error", e)
            # We reached the head of the blockchain, sleep until new block appear
            sleep(2) # TODO to change to 30s for real node

        counter += 1

        with lock:
            contracts = list(contract_dict.keys())
            if contract_hash in contracts:
                if not contract_dict[contract_hash]["bound_search"] and contract_dict[contract_hash]["status"] == "in progress":
                    contract_dict[contract_hash]["status"] = "past scanned - in progress"
                else:
                    contract_dict[contract_hash]["status"] = "finished"



def read_from_head():
    global contract_dict
    global run_head_level
    global lock

    p = pytezos.using(shell=network)

    while True:
        head = p.shell.head()
        head_level = head["header"]["level"]

        # We first check if we got a new block
        if run_head_level < head_level:
            run_head_level = head_level
            operations = head["operations"][3]

            # For each operation in the block
            for op in operations:
                op_hash = op["hash"]
                contents = op["contents"]

                # For each content
                for content in contents:
                    if "destination" in content.keys() and "parameters" in content.keys():

                        # If the destination is a contract we were asked to scan
                        if content["destination"] in contract_dict.keys():
                            if contract_dict[content["destination"]]["bound_search"] == 0 and contract_dict[content["destination"]]["status"] != "finished":
                                contract_hash = content["destination"]
                                entrypoint = content["parameters"]["entrypoint"]

                                # Get contract storage
                                storage = p.contract(contract_hash).storage(head_level)

                                if verbose:
                                    print_notification(head_level, contract_hash, entrypoint=entrypoint, storage=storage)

                                # Get notification request storage
                                data = contract_dict[contract_hash]["data"]

                                # Make notification, save contract storage if different from notification request
                                notification = make_notification(head_level, contract_hash, entrypoint=entrypoint)
                                if data[max(data.keys())] != storage:
                                    notification = make_notification(head_level, contract_hash, entrypoint=entrypoint, storage=storage)

                                # Store notification for future call
                                data[head_level] = notification
                                with lock:
                                    contract_dict[contract_hash]["data"] = data

            
        # Sleep to not spam the node
        sleep(2) # TODO to change to <30s for real node


def print_notification(lvl, contract, entrypoint=None, storage=None):
    # Print notification response
    print("Level:", lvl)
    print("Contract:", contract)
    if entrypoint != None:        
        print("Function called:", entrypoint)
    if storage != None:
        print("Storage:", storage)
    print()

def make_notification(lvl, contract, entrypoint=None, storage=None):
    # Format notification response as JSON
    notification = {}
    notification["level"]= lvl
    notification["contract"]= contract
    if entrypoint != None:
        notification["entrypoint"]= entrypoint
    if storage != None:
        for key in storage.keys():
            if type(storage[key]) not in [str, int, bytes]:
                storage[key] = str(storage[key])
        notification["storage"]= storage
    return notification

def clean_contracts():
    global contract_dict
    global lock

    # Remove notification requests already sent
    with lock:
        contracts = list(contract_dict.keys())
        for c in contracts:
            if contract_dict[c]["status"] == "sent":
                    del contract_dict[c]


@dispatcher.add_method
def get_storage(contract_hash):
    # Send contract's storage
    storage = None
    try: 
        if block_id is None:
            storage = pytezos.using(shell=network).contract(contract_hash).storage()
        else:
            storage = pytezos.using(shell=network).contract(contract_hash).storage(block_id)
    except Exception as e:
        print("Error", e)
        return {"error":str(e)}
    
    if verbose:
        print("Get contract storage:", block_id, storage, "\n")
    notification = make_notification(block_id, contract_hash, storage=storage)
    return json.dumps(notification)

@dispatcher.add_method
def contract_origin(contract_hash):
    # Send contract origin
    try:
        response = json.dumps(contract_origin_search(contract_hash))
        return response
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def list_requests():
    global lock

    try:
        # Send all notification request hashes as string
        contract_list = ""
        with lock:
            for c in contract_dict.keys():
                contract_list += c + " "
        return {"success":contract_list}

    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def clear_request(contract_hash):
    global contract_dict
    global lock

    try:
        # Delete notification request if present
        if contract_hash in contract_dict.keys():
            with lock:
                del contract_dict[contract_hash]
            return {"success": "Contract "+ str(contract_hash) + " successfully deleted."}

        else:
            return {"error": "Contract "+ str(contract_hash) + " not found."}
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def clear_all():
    global lock

    try:
        # Clear all notification requests
        with lock:
            contract_dict.clear()

        return {"success": "All requests were successfully deleted."}
    except Exception as e:
        print("Error", e)
        return {"error": str(e)}

@dispatcher.add_method
def contract_update(contract_hash, start=None, end=None):
    global contract_dict
    global lock

    response = ""

    # If notification request already present, send it to contractor and set request to "sent"
    # TODO: a contract atm can only have one requests, we can change that by using the RPC ids instead
    if contract_hash in contract_dict:
        with lock:
            response = json.dumps(contract_dict[contract_hash])
            if contract_dict[contract_hash]["status"] == "finished":
                contract_dict[contract_hash]["status"] = "sent"

        return response
    else:
        bound_search = 1
        head_level = pytezos.using(shell=network).shell.head.header()["level"]
        if end is None: 
            bound_search = 0
            end = head_level
            if run_head_level == -1:
                Thread(target=read_from_head).start()
        
        try:
            # Check contract exists
            storage = pytezos.using(shell=network).contract(contract_hash).storage(head_level)
            with lock:
                # Make new notification request
                contract_dict[contract_hash] = {"contract_hash": contract_hash, "status":"in progress", "data":{}, "bound_search":bound_search}
                if not bound_search:
                    notification = make_notification(head_level, contract_hash, entrypoint=storage["status"], storage=storage)
                    contract_dict[contract_hash]["data"][head_level] = notification
                response = json.dumps(contract_dict[contract_hash])

            Thread(target=contract_all_update_search, args=(contract_hash,), kwargs={"start":start, "end":end}).start()
            return response

        except Exception as e:
            print("Error", e)
            return {"error":"Contract "+contract_hash+" not found. \n"+str(e)}


@Request.application
def application(request):
    if verbose:
        print("---- New request:", request.data)

    # Handle request
    response = JSONRPCResponseManager.handle(request.data, dispatcher)
    if verbose:
        print("---- Response:", response.json, "\n")

    # For each new request, clean notification request list
    clean_contracts()

    return Response(response.json, mimetype='application/json')

def main():
    global network
    global verbose
    global lock

    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument("-net", "--network", type=str, help="the network, such as mainnet, or a RPC node uri", default="mainnet")
    parser.add_argument("-v", "--verbose", help="print notification updates", action="store_true")
    args = parser.parse_args()

    # Set network and get head's level
    network = args.network

    if args.verbose:
        verbose = True

    lock = Lock()

    run_simple('localhost', 4000, application)

if __name__ == '__main__':
    main()