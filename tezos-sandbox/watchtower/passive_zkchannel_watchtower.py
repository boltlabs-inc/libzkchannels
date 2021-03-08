from threading import Thread
from time import sleep
from pytezos import pytezos
import argparse

contract_dict = {}
contract_past_dict = {}
run_head_level = -1

def contract_origin_search(p, contract_hash, verbose = 0):
    start = 0
    end = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    found = -1
    data = None
    counter = 0
    while found == -1:
        counter +=1
        anchor = int((end+start+1)/2)
        try:
            data = contract.storage(block_id=anchor)
            try:
                data = contract.storage(block_id=anchor-1)
                end=anchor
            except Exception:
                found = anchor
        except Exception :
            start = anchor
    if verbose:
        print_notification(found, contract_hash, entrypoint="contract creation", storage=data)
    return found, data

def contract_all_update_search(p, contract_hash, start=-1, end=-1):
    results = []
    head_level = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    origin_level, data = contract_origin_search(p, contract_hash, verbose=1)
    start = start
    if origin_level > start or start ==-1:
        start = origin_level

    end = end
    if end > head_level or end ==-1:
        end = head_level
    # For all level between start/contract creation and now
    for lvl in range(start+1, end+1):
        if contract_hash not in contract_past_dict.keys():
            break
        storage = contract.storage(block_id=lvl)
        data = None
        user_id = None
        if (storage["status"] == "custClose" and contract_past_dict[contract_hash]["user_id"] == "merchant") or (storage["status"] == "merchClose" and contract_past_dict[contract_hash]["user_id"] == "customer"):
            # we could reuse the storage from the block but it is less readable than calling 'contract.storage'
            data = storage
            user_id = contract_past_dict[contract_hash]["user_id"]
        print_notification(lvl, contract_hash, user_id=user_id, entrypoint=storage["status"], storage=data)

        # If the status is a claim, dispute, or mutual close remove notification request (the event already passed)
        if storage["status"] in ["custClaim", "merchClaim", "merchDispute", "mutualClose"]:
            if contract_hash in contract_dict.keys():
                del contract_dict[contract_hash]
            if contract_hash in contract_past_dict.keys():
                del contract_past_dict[contract_hash]


def read_from_head(p):
    global contract_dict
    global run_head_level
    while len(contract_dict) != 0:
        head = p.shell.head()
        head_level = head["header"]["level"]
        # We first check if we got a new block
        if run_head_level < head_level:
            run_head_level = head_level
            operations = head["operations"][3]
            # For each operation
            for op in operations:
                op_hash = op["hash"]
                contents = op["contents"]
                for content in contents:
                    if "destination" in content.keys() and "parameters" in content.keys():
                        # If the destination is a contract we were asked to watch for
                        if content["destination"] in contract_dict.keys():
                            contract_hash = content["destination"]
                            entrypoint = content["parameters"]["entrypoint"]
                            storage = p.contract(contract_hash).storage(block_id=head_level)
                            data = None
                            user_id = None
                            if (storage["status"] == "custClose" and contract_past_dict[contract_hash]["user_id"] == "merchant") or (storage["status"] == "merchClose" and contract_past_dict[contract_hash]["user_id"] == "customer"):
                                # we could reuse the storage from the block but it is less readable than calling 'contract.storage'
                                data = storage
                                user_id = contract_past_dict[contract_hash]["user_id"]
                            print_notification(head_level, contract_hash, user_id=user_id, entrypoint=entrypoint, storage=data)

                            # If the operation is a claim, dispute, or mutual close remove notification request (the event already passed)
                            # but keep notification request to scan the past
                            if entrypoint in ["custClaim", "merchClaim", "merchDispute", "mutualClose"]:
                                if contract_hash in contract_dict.keys():
                                    del contract_dict[contract_hash]

        sleep(2) # TO REMOVE


def print_notification(lvl, contract, user_id=None, entrypoint=None, storage=None):
    print("Level:", lvl)
    print("Contract:", contract)
    if user_id != None:
        print("User:", user_id)
    if entrypoint != None:        
        print("Function called:", entrypoint)
    if storage != None:
        print("Storage:", storage)
    print()

def main():
    global contract_dict

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument('-c', '--contract', type=str, help="the hash of the contract to scan")
    parser.add_argument("-net", "--network", type=str, help="the network, such as mainnet, carthagenet, dalphanet, delphinet or a RPC node uri", default="mainnet")
    parser.add_argument("-id", "--identity", type=str, help="your channel identity: either customer or merchant")
    parser.add_argument("-org", "--origin", help="find the level when the contract was deployed", action="store_true")
    parser.add_argument("-stt", "--start", type=int, help="index from where to start the scan", default=-1)
    parser.add_argument("-hash", "--hash", type=int, help="block hash from where to scan")
    parser.add_argument("-end", "--end", type=int, help="index until which to start the scan (from which for last update)", default=-1)
    args = parser.parse_args()

    contract_hash = args.contract
    if args.contract is None:
        print("Error: Specify contract hash", "\n")
        return

    if args.identity is None:
        print("Error: Specify channel identity", "\n")
        return
    user_id = args.identity
    if user_id not in ["customer", "merchant"]:
        print("Error: expected 'customer' or 'merchant' as identity")
        return

    # Set network and get head's level
    network = args.network
    p = pytezos.using(shell="mainnet")
    head_level = -1
    try:
        p = pytezos.using(shell=network)
        head_level = p.shell.head.header()["level"]
    except Exception as e:
        print("Error: Network error", e, "\n")
        return

    # Set the scan lower and upper bounds
    start = args.start
    if args.hash is not None:
        try:
            block = p.shell.chains.main.blocks[args.hash]
            start = block.header()["level"]
        except Exception as e:
            print("Error: block not found", e, "\n")
            return
    end = args.end

    # Check contract exists
    ci = None
    storage = None
    try:
        ci = p.contract(contract_hash)
        storage = ci.storage(block_id=head_level)
    except Exception as e:
        print("Error: contract not found", e, "\n")
        return

    
    # Return origination's level if asked
    if args.origin == True:
        thread = Thread(target=contract_origin_search, args=(p, contract_hash,), kwargs={"verbose":1}).start()
    
    # Return all updates' levels if asked
    if args.origin == False:
        if contract_hash not in contract_dict.keys():
            end2 = head_level
            if end <= head_level:
                end2 = head_level
            contract_past_dict[contract_hash]={"last_data":storage, "user_id":user_id}
            Thread(target=contract_all_update_search, args=(p, contract_hash,), kwargs={"start":start, "end":end2}).start()
            if end == -1 or end > head_level:
                contract_dict[contract_hash]={"last_data":storage, "user_id":user_id}
                Thread(target=read_from_head, args=(p,)).start()
        else:
            print("Error: contract already being scanned.", "\n")
    

    # Start loop to enter or remove notification requests
    while len(contract_dict) != 0 and len(contract_past_dict) != 0:
        try:
            # Send hint and listen to input
            inputs = input("\n\nFunctions:\n  add <hash> --id <customer/merchant> --start <start> --end <end>\n  remove <hash>\n  list\n  kill\n\n").strip()
            inputs = inputs.split(" ")
            # Parse input and look for function
            if inputs[0].lower() in ["add", "remove", "list", "kill"]:
                if inputs[0].lower() == "kill":
                    contract_past_dict.clear()
                    contract_dict.clear()
                elif inputs[0].lower() == "list":
                    for key in contract_dict.keys():
                        print(key)
                    print("\n")
                else:
                    try:
                        contract_hash = inputs[1]
                        storage = p.contract(contract_hash).storage()
                        originated_level, originated_data = contract_origin_search(p, contract_hash)
                        head_level = p.shell.head.header()["level"]
                        
                        # Check scan lower bound
                        start = -1
                        if "--start" in inputs:
                            stt = int(inputs[inputs.index("--start")+1])
                            start = stt
                            if stt < originated_level:
                                start = originated_level
                        
                        # Check scan upper bound
                        end = -1
                        if "--end" in inputs:
                            end = int(inputs[inputs.index("--end")+1])

                        if "--id" not in inputs:
                            print("id needed")
                            break
                        user_id = inputs[inputs.index("--id")+1]
                        if user_id not in ["customer", "merchant"]:
                            print("wrong identifier")
                            break

                        # Return all updates' levels if asked
                        if inputs[0] == "add":
                            end2 = head_level
                            if end <= head_level:
                                end2 = end
                            contract_past_dict[contract_hash]={"last_data":storage, "user_id":user_id}
                            Thread(target=contract_all_update_search, args=(p, contract_hash,), kwargs={"start":start, "end":end2}).start()
                            if (end == -1 or end > head_level) and contract_hash not in contract_dict.keys():
                                contract_dict[contract_hash]={"last_data":storage, "user_id":user_id}

                        if inputs[0] == "remove":
                            if contract_hash in contract_dict.keys():
                                if user_id == contract_dict[contract_hash]["user_id"]:
                                    del contract_dict[contract_hash]
                                    print("Contract "+str(contract_hash)+" removed.\n")



                    except Exception as e:
                        print("Error: contract not found", e, "\n")
            
            else:
                print("Error command not recognized", inputs, "\n")
        

        except Exception as e:
            print(e)
    print("No more contract to scan, closing program.\n")


def test_contract_origin():
    contract = "KT19kgnqC5VWoxktLRdRUERbyUPku9YioE8W"
    origin_lvl = 1073618
    lvl, _ = contract_origin_search("mainnet", contract)
    assert origin_lvl == lvl


if __name__ == "__main__":
    main()

