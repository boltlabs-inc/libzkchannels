from threading import Thread
from time import sleep
from pytezos import pytezos
import argparse

contract_dict = {}

def contract_origin_search(p, contract_hash, verbose = 0):
    start = 0
    end = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    found = -1
    data = None
    while found == -1:
        anchor = int((end+start)/2)
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
        print("Ntf origin:", contract_hash, found, data, "\n")
    return found, data

def contract_all_update_search(p, contract_hash, start=-1, end=-1):
    results = []
    head_level = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    origin_level, data = contract_origin_search(p, contract_hash, verbose=1)
    start = start
    if origin_level > start or start ==-1:
        start = origin_level
        results.append([origin_level, data])
    else:
        data = contract.storage(block_id=start)
        results.append([start, data])
    end = end
    if end > head_level or end ==-1:
        end = head_level
    for lvl in range(start+1, end+1):
        if contract_hash not in contract_dict.keys():
            break
        data = contract.storage(block_id=lvl)
        if data != results[len(results)-1][1]:
            print("Ntf past", contract_hash, lvl, data, "\n")
            results.append([lvl, data])
            sleep(2) # TO REMOVE, added as test vector has too many updates
    return start, end, results

def contract_first_update_search(p, contract_hash, start=-1):
    head_level = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    origin_level, data = contract_origin_search(p, contract_hash)
    if start > head_level:
        return -1, [-1, None]
    start = start
    if origin_level > start:
        start = origin_level

    for lvl in range(start+1, head_level+1):
        new_data = contract.storage(block_id=lvl)
        if new_data != data:
            print("Ntf first:", contract_hash, start, lvl, new_data, "\n")
            return start, [lvl, new_data]
    return start, [-1, None]

def contract_last_update_search(p, contract_hash, end=-1):
    head_level = p.shell.head.header()["level"]
    contract = p.contract(contract_hash)
    origin_level, data = contract_origin_search(p, contract_hash)
    if end > 0 and end < origin_level:
        return -1, [-1, None]
    end = end
    if end == -1 or end > head_level:
        end = head_level

    for lvl in range(end, origin_level, -1):
        new_data = contract.storage(block_id=lvl)
        prev_data = contract.storage(block_id=lvl-1)
        if new_data != prev_data:
            print("Ntf end:", contract_hash, end, lvl, new_data, "\n")
            return end, [lvl, new_data]
    return end, [-1, None]

def read_from_head(p):
    global contract_dict
    while len(contract_dict) != 0:
        for contract_hash in contract_dict.keys():
            head_level = p.shell.head.header()["level"]
            data = p.contract(contract_hash).storage(block_id=head_level)
            if data != contract_dict[contract_hash]["last_data"]:
                print("Ntf head:", contract_hash, head_level, data, "\n")
                contract_dict[contract_hash]["last_data"] = data
        sleep(5) # TO REMOVE



def main():
    global contract_dict

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument('-c', '--contract', type=str, help="the hash of the contract to scan")
    parser.add_argument("-net", "--network", type=str, help="the network, such as mainnet, carthagenet, dalphanet, delphinet or a RPC node uri", default="mainnet")
    parser.add_argument("-org", "--origin", help="find the level when the contract was deployed", action="store_true")
    parser.add_argument("-fst", "--first", help="find the contract's first update", action="store_true")
    parser.add_argument("-lst", "--last", help="find the contract's last update", action="store_true")
    parser.add_argument("-stt", "--start", type=int, help="index from where to start the scan", default=-1)
    parser.add_argument("-hash", "--hash", type=int, help="block hash from where to scan")
    parser.add_argument("-end", "--end", type=int, help="index until which to start the scan (from which for last update)", default=-1)
    args = parser.parse_args()

    contract_hash = args.contract
    if args.contract is None:
        print("Error: Specify contract hash", "\n")
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

    
    # Return first update's level if asked
    if args.first == True:
        Thread(target=contract_first_update_search, args=(p, contract_hash,), kwargs={"start":start}).start()
    
    # Return last update's level if asked
    if args.last == True:
        thread = Thread(target=contract_last_update_search, args=(p, contract_hash,), kwargs={"end":end}).start()
    
    # Return origination's level if asked
    if args.origin == True:
        thread = Thread(target=contract_origin_search, args=(p, contract_hash,), kwargs={"verbose":1}).start()
    
    # Return all updates' levels if asked
    if (args.first == False and args.last == False and args.origin == False):
        if contract_hash not in contract_dict.keys():
            end2 = head_level
            if end <= head_level:
                end2 = head_level
            Thread(target=contract_all_update_search, args=(p, contract_hash,), kwargs={"start":start, "end":end2}).start()
            if end == -1 or end > head_level:
                contract_dict[contract_hash]={"last_data":storage}
                Thread(target=read_from_head, args=(p,)).start()
        else:
            print("Error: contract already being scanned.", "\n")
    

    # Start loop to enter or remove notification requests
    while len(contract_dict) != 0:
        try:
            # Send hint and listen to input
            inputs = input("\n\nFunctions:\n  add <hash> --start <start> --end <end>\n  remove <hash>\n  origin <hash> \n  first <hash> --start <start>\n  last <hash> --end <end>\n  list\n\n").strip()
            inputs = inputs.split(" ")
            # Parse input and look for function
            if inputs[0].lower() in ["add", "remove", "origin", "first", "last", "list"]:
                if inputs[0].lower() == "list":
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

                        # Return first update's level if asked
                        if inputs[0] == "first":
                            Thread(target=contract_first_update_search, args=(p, contract_hash,), kwargs={"start":start}).start()
                        
                        # Return last update's level if asked
                        if inputs[0] == "last":
                            Thread(target=contract_last_update_search, args=(p, contract_hash,), kwargs={"end":end}).start()
                        
                        # Return origination's level if asked
                        if inputs[0] == "origin":
                            Thread(target=contract_origin_search, args=(p, contract_hash,), kwargs={"verbose":1}).start()
                        
                        # Return all updates' levels if asked
                        if inputs[0] == "add":
                            end2 = head_level
                            if end <= head_level:
                                end2 = end
                            Thread(target=contract_all_update_search, args=(p, contract_hash,), kwargs={"start":start, "end":end2}).start()
                            if (end == -1 or end > head_level) and contract_hash not in contract_dict.keys():
                                contract_dict[contract_hash]={"last_data":storage}

                        if inputs[0] == "remove":
                            if contract_hash in contract_dict.keys():
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

def test_contract_first_update():
    contract = "KT19kgnqC5VWoxktLRdRUERbyUPku9YioE8W"
    first_update_lvl = 1073622
    start, [lvl, _] = contract_first_update_search("mainnet", contract)
    assert first_update_lvl == lvl


if __name__ == "__main__":
    main()

